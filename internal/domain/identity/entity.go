// Package identity defines the core user identity aggregate for the SSO hub.
package identity

import (
	"time"

	"github.com/google/uuid"
)

// MFAMethod enumerates the MFA mechanisms a user may have enrolled.
type MFAMethod string

const (
	MFAMethodTOTP     MFAMethod = "totp"
	MFAMethodWebAuthn MFAMethod = "webauthn"
	MFAMethodSMS      MFAMethod = "sms"
)

// Status controls whether a user is permitted to authenticate.
type Status string

const (
	StatusActive    Status = "active"
	StatusSuspended Status = "suspended"
	StatusDeleted   Status = "deleted"
)

// User is the root aggregate for the identity domain.
// All fields map directly to the sso_users PostgreSQL table.
type User struct {
	ID             uuid.UUID
	CasdoorID      string // external ID assigned by Casdoor; used for SCIM correlation
	Email          string
	DisplayName    string
	AvatarURL      string
	OrganizationID string
	Status         Status
	MFAEnabled     bool
	MFAMethods     []MFAMethod
	// ExternalIDs stores provider-specific IDs (e.g., Azure OID, SCIM externalId).
	ExternalIDs map[string]string
	LastLoginAt *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// NewUser creates a new User aggregate with a generated UUID and default status.
func NewUser(casdoorID, email, displayName, orgID string) *User {
	now := time.Now().UTC()
	return &User{
		ID:             uuid.New(),
		CasdoorID:      casdoorID,
		Email:          email,
		DisplayName:    displayName,
		OrganizationID: orgID,
		Status:         StatusActive,
		ExternalIDs:    make(map[string]string),
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

// IsActive returns true when the user is permitted to authenticate.
func (u *User) IsActive() bool {
	return u.Status == StatusActive
}

// RecordLogin stamps the last login timestamp; call this after successful authentication.
func (u *User) RecordLogin() {
	now := time.Now().UTC()
	u.LastLoginAt = &now
	u.UpdatedAt = now
}

// Suspend marks the user as suspended, preventing future logins.
func (u *User) Suspend() {
	u.Status = StatusSuspended
	u.UpdatedAt = time.Now().UTC()
}
