package session

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	apperrors "github.com/enterprise/sso-identity-hub/pkg/errors"
)

// Service is the domain service for session lifecycle management.
type Service struct {
	repo   Repository
	maxAge time.Duration
}

// NewService constructs the session domain service.
// maxAge is the token policy lifetime (e.g., 8h) enforced at session creation.
func NewService(repo Repository, maxAge time.Duration) *Service {
	return &Service{repo: repo, maxAge: maxAge}
}

// CreateSession builds and persists a new authenticated session aggregate.
func (s *Service) CreateSession(
	ctx context.Context,
	userID uuid.UUID,
	sid, accessToken, refreshToken, clientID, ip, ua string,
) (*Session, error) {
	sess := NewSession(userID, sid, accessToken, refreshToken, clientID, ip, ua, s.maxAge)
	if err := s.repo.Save(ctx, sess); err != nil {
		return nil, apperrors.Internal("create session: persist failed", err)
	}
	return sess, nil
}

// GetBySID looks up an active session by its OIDC sid claim.
// Returns a typed error if the session is not found, expired, or already revoked.
func (s *Service) GetBySID(ctx context.Context, sid string) (*Session, error) {
	sess, err := s.repo.FindBySID(ctx, sid)
	if err != nil {
		return nil, apperrors.NotFound("session not found for sid", err)
	}

	if !sess.IsActive() {
		return nil, apperrors.SessionExpired("session has expired or been revoked")
	}

	return sess, nil
}

// RevokeSession invalidates a single session by its internal ID.
func (s *Service) RevokeSession(ctx context.Context, id uuid.UUID) error {
	sess, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return apperrors.NotFound("session not found", err)
	}

	if sess.State == StateRevoked {
		// Idempotent: revoking an already-revoked session is a no-op.
		return nil
	}

	if err := s.repo.Revoke(ctx, id); err != nil {
		return apperrors.Internal("revoke session failed", err)
	}

	return nil
}

// RevokeAllUserSessions terminates every active session for the given user.
// Returns the list of revoked sessions so the caller can dispatch logout tokens.
func (s *Service) RevokeAllUserSessions(ctx context.Context, userID uuid.UUID) ([]*Session, error) {
	active, err := s.repo.FindActiveByUserID(ctx, userID)
	if err != nil {
		return nil, apperrors.Internal("list active sessions failed", err)
	}

	if len(active) == 0 {
		return nil, nil
	}

	if err := s.repo.RevokeAllForUser(ctx, userID); err != nil {
		return nil, apperrors.Internal("revoke all sessions failed", err)
	}

	return active, nil
}

// ValidateSession returns the session if it is active, or an appropriate typed error.
func (s *Service) ValidateSession(ctx context.Context, id uuid.UUID) (*Session, error) {
	sess, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, apperrors.NotFound(fmt.Sprintf("session %s not found", id), err)
	}

	if !sess.IsActive() {
		return nil, apperrors.SessionExpired("session is no longer valid")
	}

	return sess, nil
}
