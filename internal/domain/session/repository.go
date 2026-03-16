package session

import (
	"context"

	"github.com/google/uuid"
)

// Repository is the persistence contract for session aggregates.
type Repository interface {
	// Save persists a new session record.
	Save(ctx context.Context, s *Session) error

	// FindByID retrieves a session by its internal UUID.
	FindByID(ctx context.Context, id uuid.UUID) (*Session, error)

	// FindBySID retrieves a session by the OIDC sid claim.
	// This is the primary lookup path during back-channel logout processing.
	FindBySID(ctx context.Context, sid string) (*Session, error)

	// FindActiveByUserID returns all non-revoked, non-expired sessions for a user.
	// Used to build the full list of sessions to terminate on a forced logout.
	FindActiveByUserID(ctx context.Context, userID uuid.UUID) ([]*Session, error)

	// Revoke marks a single session as revoked and stamps revokedAt.
	Revoke(ctx context.Context, id uuid.UUID) error

	// RevokeAllForUser revokes all active sessions for a user in a single operation.
	// This is called during account suspension or admin-initiated forced logout.
	RevokeAllForUser(ctx context.Context, userID uuid.UUID) error

	// DeleteExpired removes sessions whose expiry timestamp has passed.
	// Intended for periodic background cleanup jobs.
	DeleteExpired(ctx context.Context) (int64, error)
}
