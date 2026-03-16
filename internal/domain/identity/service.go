package identity

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	apperrors "github.com/enterprise/sso-identity-hub/pkg/errors"
)

// Service encapsulates business rules for the identity domain.
// It owns the only write path to User aggregates; HTTP handlers must not
// call the Repository directly.
type Service struct {
	repo Repository
}

// NewService wires the domain service with its repository dependency.
func NewService(repo Repository) *Service {
	return &Service{repo: repo}
}

// ProvisionUser creates or updates a local User record from an inbound Casdoor identity.
// This is called after a successful OIDC token exchange to keep local state in sync.
func (s *Service) ProvisionUser(ctx context.Context, casdoorID, email, displayName, orgID string) (*User, error) {
	existing, err := s.repo.FindByCasdoorID(ctx, casdoorID)
	if err == nil {
		// User already exists; update display name in case it was changed upstream.
		existing.DisplayName = displayName
		existing.UpdatedAt = existing.UpdatedAt // trigger UpdatedAt refresh handled by Save
		if saveErr := s.repo.Save(ctx, existing); saveErr != nil {
			return nil, fmt.Errorf("update existing user: %w", saveErr)
		}
		return existing, nil
	}

	// Only create a net-new record when the lookup returned a genuine not-found signal.
	if !isNotFound(err) {
		return nil, fmt.Errorf("lookup casdoor user %q: %w", casdoorID, err)
	}

	user := NewUser(casdoorID, email, displayName, orgID)
	if saveErr := s.repo.Save(ctx, user); saveErr != nil {
		return nil, fmt.Errorf("persist new user: %w", saveErr)
	}

	return user, nil
}

// GetUser returns a user by internal UUID, returning a typed not-found error
// when absent so callers can branch without string matching.
func (s *Service) GetUser(ctx context.Context, id uuid.UUID) (*User, error) {
	user, err := s.repo.FindByID(ctx, id)
	if err != nil {
		if isNotFound(err) {
			return nil, apperrors.NotFound(fmt.Sprintf("user %s not found", id), err)
		}
		return nil, apperrors.Internal("get user failed", err)
	}
	return user, nil
}

// SuspendUser locks a user account immediately. Because the OIDC token lifetime
// is short (≤8h per policy), suspension takes effect at the next token refresh.
// For immediate lockout, call MSGraph.RevokeTokens in the application layer.
func (s *Service) SuspendUser(ctx context.Context, id uuid.UUID) error {
	if err := s.repo.UpdateStatus(ctx, id, StatusSuspended); err != nil {
		return apperrors.Internal("suspend user failed", err)
	}
	return nil
}

// RecordSuccessfulLogin stamps last_login_at for audit and analytics purposes.
func (s *Service) RecordSuccessfulLogin(ctx context.Context, id uuid.UUID) error {
	if err := s.repo.UpdateLastLogin(ctx, id); err != nil {
		return apperrors.Internal("record login failed", err)
	}
	return nil
}

func isNotFound(err error) bool {
	return err != nil && fmt.Sprintf("%v", err) == apperrors.ErrNotFound.Error()
}
