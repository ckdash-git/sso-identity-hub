// Package provisioning coordinates user lifecycle events between the identity
// domain, Casdoor, and downstream SCIM service providers.
package provisioning

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/google/uuid"

	"github.com/enterprise/sso-identity-hub/internal/domain/identity"
	"github.com/enterprise/sso-identity-hub/internal/infrastructure/scim"
	apperrors "github.com/enterprise/sso-identity-hub/pkg/errors"
)

// Service handles user provisioning and deprovisioning to external SCIM endpoints.
type Service struct {
	identitySvc *identity.Service
	scimClient  *scim.Client
	logger      *zap.Logger
}

// NewService wires the provisioning application service.
func NewService(identitySvc *identity.Service, scimClient *scim.Client, logger *zap.Logger) *Service {
	return &Service{
		identitySvc: identitySvc,
		scimClient:  scimClient,
		logger:      logger,
	}
}

// ProvisionToSCIM pushes a user's current state to the downstream SCIM endpoint.
// It is called after profile changes propagate from Casdoor into the local identity store.
func (s *Service) ProvisionToSCIM(ctx context.Context, userID uuid.UUID) error {
	user, err := s.identitySvc.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("get user for scim provisioning: %w", err)
	}

	scimUser := mapUserToSCIM(user)

	if err := s.scimClient.ProvisionUser(ctx, scimUser); err != nil {
		s.logger.Error("scim provisioning failed",
			zap.String("user_id", userID.String()),
			zap.String("email", user.Email),
			zap.Error(err),
		)
		return apperrors.New(apperrors.ErrProvisioningFailed, "scim provisioning failed", 502, err)
	}

	s.logger.Info("user provisioned to scim",
		zap.String("user_id", userID.String()),
		zap.String("email", user.Email),
	)
	return nil
}

// DeprovisionFromSCIM marks a user as inactive at the downstream SCIM endpoint.
// Called when a user is suspended or deleted from the identity hub.
func (s *Service) DeprovisionFromSCIM(ctx context.Context, userID uuid.UUID) error {
	user, err := s.identitySvc.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("get user for scim deprovisioning: %w", err)
	}

	if err := s.scimClient.DeprovisionUser(ctx, user.CasdoorID); err != nil {
		s.logger.Error("scim deprovisioning failed",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return apperrors.New(apperrors.ErrProvisioningFailed, "scim deprovisioning failed", 502, err)
	}

	s.logger.Info("user deprovisioned from scim",
		zap.String("user_id", userID.String()),
	)
	return nil
}

// mapUserToSCIM converts an identity.User aggregate to a SCIM 2.0 User resource.
func mapUserToSCIM(user *identity.User) scim.SCIMUser {
	scimUser := scim.SCIMUser{
		ExternalID:  user.CasdoorID,
		UserName:    user.Email,
		DisplayName: user.DisplayName,
		Active:      user.IsActive(),
		Emails: []scim.SCIMEmail{
			{Value: user.Email, Primary: true, Type: "work"},
		},
	}

	if user.AvatarURL != "" {
		scimUser.Photos = []scim.SCIMPhoto{{Value: user.AvatarURL, Type: "photo"}}
	}

	return scimUser
}
