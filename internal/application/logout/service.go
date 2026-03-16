// Package logout implements the OIDC Back-Channel Logout 1.0 application service.
// On logout it: revokes the local session, mints RS256 logout tokens, fans them
// out to all registered third-party endpoints, and optionally revokes Azure AD
// refresh tokens via the Microsoft Graph API for immediate hard lockout.
package logout

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/google/uuid"

	"github.com/enterprise/sso-identity-hub/internal/config"
	"github.com/enterprise/sso-identity-hub/internal/domain/identity"
	"github.com/enterprise/sso-identity-hub/internal/domain/session"
	"github.com/enterprise/sso-identity-hub/internal/infrastructure/msgraph"
	jwtpkg "github.com/enterprise/sso-identity-hub/pkg/jwt"
)

// AuditLogger is a minimal interface for persisting back-channel logout delivery records.
// It is kept narrow so the application layer is not coupled to the full DB package.
type AuditLogger interface {
	LogDelivery(ctx context.Context, record DeliveryRecord) error
	MarkDelivered(ctx context.Context, id uuid.UUID) error
	MarkFailed(ctx context.Context, id uuid.UUID, errMsg string) error
}

// DeliveryRecord captures the outcome of a single logout token delivery attempt.
type DeliveryRecord struct {
	ID          uuid.UUID
	SessionID   uuid.UUID
	UserID      uuid.UUID
	EndpointURL string
	LogoutToken string
}

// Service orchestrates the full back-channel logout flow.
type Service struct {
	sessionSvc  *session.Service
	identitySvc *identity.Service
	jwtSvc      *jwtpkg.Service
	graphClient *msgraph.Client
	auditLog    AuditLogger
	cfg         config.Config
	logger      *zap.Logger
	httpClient  *http.Client
}

// NewService wires the logout application service.
func NewService(
	sessionSvc *session.Service,
	identitySvc *identity.Service,
	jwtSvc *jwtpkg.Service,
	graphClient *msgraph.Client,
	auditLog AuditLogger,
	cfg config.Config,
	logger *zap.Logger,
) *Service {
	return &Service{
		sessionSvc:  sessionSvc,
		identitySvc: identitySvc,
		jwtSvc:      jwtSvc,
		graphClient: graphClient,
		auditLog:    auditLog,
		cfg:         cfg,
		logger:      logger,
		httpClient:  &http.Client{Timeout: cfg.BackChannel.Timeout},
	}
}

// LogoutInput carries the parameters needed to initiate a logout.
type LogoutInput struct {
	// UserID is the internal UUID of the user being logged out.
	UserID uuid.UUID
	// SessionID is the internal UUID of the specific session to terminate.
	// If nil, all sessions for the user are terminated (admin forced logout).
	SessionID *uuid.UUID
	// AzureObjectID is optional. When set, the MS Graph revocation call is made.
	AzureObjectID string
}

// Logout revokes the session(s), fans out logout tokens, and optionally hard-revokes
// Azure AD refresh tokens. Errors in back-channel delivery are logged but do not
// cause the overall logout to fail — the local session is always revoked first.
func (s *Service) Logout(ctx context.Context, input LogoutInput) error {
	var sessions []*session.Session
	var err error

	if input.SessionID != nil {
		sess, err := s.sessionSvc.ValidateSession(ctx, *input.SessionID)
		if err != nil {
			if isExpiredOrNotFound(err) {
				// Session is already gone; treat as success.
				return nil
			}
			return fmt.Errorf("lookup session: %w", err)
		}
		sessions = []*session.Session{sess}
		if rErr := s.sessionSvc.RevokeSession(ctx, *input.SessionID); rErr != nil {
			return fmt.Errorf("revoke session: %w", rErr)
		}
	} else {
		sessions, err = s.sessionSvc.RevokeAllUserSessions(ctx, input.UserID)
		if err != nil {
			return fmt.Errorf("revoke all sessions: %w", err)
		}
	}

	// Fire-and-forget back-channel notifications. We use a WaitGroup so the
	// audit log captures all results before the function returns, but we do not
	// block the response on individual endpoint latency beyond the client timeout.
	var wg sync.WaitGroup
	for _, sess := range sessions {
		for _, endpoint := range s.cfg.BackChannel.Endpoints {
			wg.Add(1)
			go func(sess *session.Session, endpoint string) {
				defer wg.Done()
				s.deliverLogoutToken(ctx, sess, input.UserID, endpoint)
			}(sess, endpoint)
		}
	}
	wg.Wait()

	// Hard-revoke Azure AD tokens when the caller provides an object ID.
	// This ensures the refresh token is invalidated even before it expires.
	if input.AzureObjectID != "" && s.graphClient != nil {
		if rErr := s.graphClient.RevokeUserRefreshTokens(ctx, input.AzureObjectID); rErr != nil {
			// MS Graph failure is logged but non-fatal; the local session is already gone.
			s.logger.Warn("ms graph token revocation failed",
				zap.String("azure_oid", input.AzureObjectID),
				zap.Error(rErr),
			)
		}
	}

	return nil
}

// deliverLogoutToken mints a logout token and POSTs it to a single downstream endpoint.
func (s *Service) deliverLogoutToken(ctx context.Context, sess *session.Session, userID uuid.UUID, endpoint string) {
	record := DeliveryRecord{
		ID:          uuid.New(),
		SessionID:   sess.ID,
		UserID:      userID,
		EndpointURL: endpoint,
	}

	logoutToken, err := s.jwtSvc.MintLogoutToken(sess.UserID.String(), sess.SID)
	if err != nil {
		s.logger.Error("mint logout token failed", zap.Error(err), zap.String("endpoint", endpoint))
		if s.auditLog != nil {
			_ = s.auditLog.MarkFailed(ctx, record.ID, err.Error())
		}
		return
	}
	record.LogoutToken = logoutToken

	if s.auditLog != nil {
		_ = s.auditLog.LogDelivery(ctx, record)
	}

	for attempt := 1; attempt <= s.cfg.BackChannel.MaxRetries; attempt++ {
		deliveryErr := s.post(endpoint, logoutToken)
		if deliveryErr == nil {
			s.logger.Info("back-channel logout delivered",
				zap.String("endpoint", endpoint),
				zap.String("sid", sess.SID),
				zap.Int("attempt", attempt),
			)
			if s.auditLog != nil {
				_ = s.auditLog.MarkDelivered(ctx, record.ID)
			}
			return
		}

		s.logger.Warn("back-channel logout delivery attempt failed",
			zap.String("endpoint", endpoint),
			zap.Int("attempt", attempt),
			zap.Error(deliveryErr),
		)

		if attempt < s.cfg.BackChannel.MaxRetries {
			time.Sleep(time.Duration(attempt*attempt) * 100 * time.Millisecond) // exponential back-off
		}
	}

	s.logger.Error("back-channel logout delivery exhausted retries", zap.String("endpoint", endpoint))
	if s.auditLog != nil {
		_ = s.auditLog.MarkFailed(ctx, record.ID, "max retries exceeded")
	}
}

// post performs the HTTP POST of the logout_token form parameter to the endpoint.
// OIDC spec requires the token be sent as application/x-www-form-urlencoded.
func (s *Service) post(endpoint, logoutToken string) error {
	body := []byte("logout_token=" + logoutToken)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("post logout token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("endpoint returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func isExpiredOrNotFound(err error) bool {
	return err != nil && (err.Error() == "session expired" || err == sql.ErrNoRows)
}
