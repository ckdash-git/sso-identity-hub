// Package token handles PKCE verification and token metadata for OAuth flows.
package token

import (
	"time"

	"github.com/google/uuid"
)

// TokenType distinguishes between access and refresh tokens in audit records.
type TokenType string

const (
	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh"
	TokenTypeID      TokenType = "id"
)

// TokenRecord is an audit log entry for issued tokens.
// It is not used for validation — Casdoor is the authoritative token store.
// Its purpose is to support forced-revocation queries (e.g., MS Graph calls).
type TokenRecord struct {
	ID        uuid.UUID
	SessionID uuid.UUID
	UserID    uuid.UUID
	TokenType TokenType
	// JTI is the "jti" claim from the JWT, used as the lookup key for revocation.
	JTI string
	// ExternalRefID holds the provider-specific token ID (e.g., Azure objectId for MS Graph).
	ExternalRefID string
	IssuedAt      time.Time
	ExpiresAt     time.Time
	RevokedAt     *time.Time
}

// IsRevoked returns true if the token has been explicitly revoked.
func (t *TokenRecord) IsRevoked() bool {
	return t.RevokedAt != nil
}

// IsExpired returns true if the token's expiry time has passed.
func (t *TokenRecord) IsExpired() bool {
	return time.Now().UTC().After(t.ExpiresAt)
}
