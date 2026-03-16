// Package session manages the lifecycle of authenticated browser sessions
// and their associated OIDC sid values, which are the key to back-channel logout.
package session

import (
	"time"

	"github.com/google/uuid"
)

// State represents the current lifecycle state of a session.
type State string

const (
	StateActive  State = "active"
	StateRevoked State = "revoked"
	StateExpired State = "expired"
)

// Session is the aggregate root for an authenticated user session.
// The sid field is the OIDC Session ID issued by Casdoor and embedded in ID tokens;
// it is the correlation key used in back-channel logout tokens.
type Session struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	SID          string // OIDC session identifier (sid claim)
	AccessToken  string // opaque — stored for immediate revocation lookups
	RefreshToken string // opaque — stored for MS Graph revocation calls
	ClientID     string // the OIDC relying party that initiated this session
	IPAddress    string
	UserAgent    string
	State        State
	ExpiresAt    time.Time
	CreatedAt    time.Time
	RevokedAt    *time.Time
}

// NewSession constructs an active session aggregate.
func NewSession(userID uuid.UUID, sid, accessToken, refreshToken, clientID, ip, ua string, ttl time.Duration) *Session {
	now := time.Now().UTC()
	return &Session{
		ID:           uuid.New(),
		UserID:       userID,
		SID:          sid,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ClientID:     clientID,
		IPAddress:    ip,
		UserAgent:    ua,
		State:        StateActive,
		ExpiresAt:    now.Add(ttl),
		CreatedAt:    now,
	}
}

// IsActive returns true if the session has not been revoked and has not expired.
func (s *Session) IsActive() bool {
	return s.State == StateActive && time.Now().UTC().Before(s.ExpiresAt)
}

// Revoke marks the session as revoked. The caller is responsible for persisting
// this state change and dispatching back-channel logout notifications.
func (s *Session) Revoke() {
	now := time.Now().UTC()
	s.State = StateRevoked
	s.RevokedAt = &now
}
