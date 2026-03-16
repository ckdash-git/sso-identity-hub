package identity

import (
	"context"

	"github.com/google/uuid"
)

// Repository is the persistence contract for the identity domain.
// Infrastructure implementations (postgres, in-memory for tests) must satisfy this interface.
type Repository interface {
	// FindByID retrieves a user by their internal UUID.
	FindByID(ctx context.Context, id uuid.UUID) (*User, error)

	// FindByEmail retrieves a user by email address. Used during OIDC claim resolution.
	FindByEmail(ctx context.Context, email string) (*User, error)

	// FindByCasdoorID resolves the local user record from the Casdoor external ID.
	FindByCasdoorID(ctx context.Context, casdoorID string) (*User, error)

	// Save upserts a user record. Creates if not present, updates otherwise.
	Save(ctx context.Context, user *User) error

	// UpdateStatus changes the user's active/suspended/deleted status.
	UpdateStatus(ctx context.Context, id uuid.UUID, status Status) error

	// UpdateLastLogin stamps the last_login_at column after a successful auth event.
	UpdateLastLogin(ctx context.Context, id uuid.UUID) error

	// Delete performs a soft-delete by setting status = 'deleted'.
	Delete(ctx context.Context, id uuid.UUID) error
}
