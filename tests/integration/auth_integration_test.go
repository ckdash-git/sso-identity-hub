package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/enterprise/sso-identity-hub/internal/domain/identity"
	"github.com/enterprise/sso-identity-hub/internal/domain/session"
	"github.com/enterprise/sso-identity-hub/internal/infrastructure/database/repository"
	apperrors "github.com/enterprise/sso-identity-hub/pkg/errors"
	"github.com/enterprise/sso-identity-hub/tests/integration/testhelpers"
)

// TestIdentityRepository_SaveAndFindByID exercises the full upsert→fetch lifecycle
// against a real PostgreSQL schema, validating constraint and serialisation correctness.
func TestIdentityRepository_SaveAndFindByID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	td := testhelpers.NewTestDatabase(t)
	repo := repository.NewPostgresIdentityRepository(td.DB)
	ctx := context.Background()

	user := identity.NewUser("casdoor-id-001", "alice@example.com", "Alice", "org-1")
	user.MFAEnabled = true
	user.MFAMethods = []identity.MFAMethod{identity.MFAMethodTOTP}
	user.ExternalIDs = map[string]string{"azure": "azure-oid-abc"}

	err := repo.Save(ctx, user)
	require.NoError(t, err)

	fetched, err := repo.FindByID(ctx, user.ID)
	require.NoError(t, err)

	assert.Equal(t, user.ID, fetched.ID)
	assert.Equal(t, "alice@example.com", fetched.Email)
	assert.Equal(t, "Alice", fetched.DisplayName)
	assert.True(t, fetched.MFAEnabled)
	assert.Contains(t, fetched.MFAMethods, identity.MFAMethodTOTP)
	assert.Equal(t, "azure-oid-abc", fetched.ExternalIDs["azure"])
}

func TestIdentityRepository_FindByEmail_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	td := testhelpers.NewTestDatabase(t)
	repo := repository.NewPostgresIdentityRepository(td.DB)
	ctx := context.Background()

	_, err := repo.FindByEmail(ctx, "nonexistent@example.com")
	assert.ErrorIs(t, err, apperrors.ErrNotFound)
}

func TestIdentityRepository_UpdateStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	td := testhelpers.NewTestDatabase(t)
	repo := repository.NewPostgresIdentityRepository(td.DB)
	ctx := context.Background()

	user := identity.NewUser("casdoor-id-002", "bob@example.com", "Bob", "org-1")
	require.NoError(t, repo.Save(ctx, user))

	err := repo.UpdateStatus(ctx, user.ID, identity.StatusSuspended)
	require.NoError(t, err)

	// Suspended user should no longer appear in active queries.
	fetched, err := repo.FindByID(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, identity.StatusSuspended, fetched.Status)
}

// ---------------------------------------------------------------------------
// Session repository integration tests
// ---------------------------------------------------------------------------

func TestSessionRepository_SaveAndFindBySID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	td := testhelpers.NewTestDatabase(t)

	// Create a user first to satisfy the FK constraint.
	identityRepo := repository.NewPostgresIdentityRepository(td.DB)
	ctx := context.Background()
	user := identity.NewUser("casdoor-id-003", "carol@example.com", "Carol", "org-1")
	require.NoError(t, identityRepo.Save(ctx, user))

	sessionRepo := repository.NewPostgresSessionRepository(td.DB)
	sess := session.NewSession(user.ID, "oidc-sid-abc", "access-token-1", "refresh-token-1", "client-app", "10.0.0.1", "TestAgent/1.0", 8*time.Hour)

	err := sessionRepo.Save(ctx, sess)
	require.NoError(t, err)

	fetched, err := sessionRepo.FindBySID(ctx, "oidc-sid-abc")
	require.NoError(t, err)

	assert.Equal(t, sess.ID, fetched.ID)
	assert.Equal(t, user.ID, fetched.UserID)
	assert.Equal(t, session.StateActive, fetched.State)
	assert.True(t, fetched.IsActive())
}

func TestSessionRepository_Revoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	td := testhelpers.NewTestDatabase(t)
	ctx := context.Background()

	identityRepo := repository.NewPostgresIdentityRepository(td.DB)
	user := identity.NewUser("casdoor-id-004", "dave@example.com", "Dave", "org-1")
	require.NoError(t, identityRepo.Save(ctx, user))

	sessionRepo := repository.NewPostgresSessionRepository(td.DB)
	sess := session.NewSession(user.ID, "oidc-sid-revoke", "at", "rt", "client", "127.0.0.1", "ua", 8*time.Hour)
	require.NoError(t, sessionRepo.Save(ctx, sess))

	err := sessionRepo.Revoke(ctx, sess.ID)
	require.NoError(t, err)

	fetched, err := sessionRepo.FindByID(ctx, sess.ID)
	require.NoError(t, err)
	assert.Equal(t, session.StateRevoked, fetched.State)
	assert.NotNil(t, fetched.RevokedAt)
}

func TestSessionRepository_RevokeAllForUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	td := testhelpers.NewTestDatabase(t)
	ctx := context.Background()

	identityRepo := repository.NewPostgresIdentityRepository(td.DB)
	user := identity.NewUser("casdoor-id-005", "eve@example.com", "Eve", "org-1")
	require.NoError(t, identityRepo.Save(ctx, user))

	sessionRepo := repository.NewPostgresSessionRepository(td.DB)

	for i := 0; i < 3; i++ {
		sid := uuid.New().String()
		s := session.NewSession(user.ID, sid, "at", "rt", "client", "127.0.0.1", "ua", 8*time.Hour)
		require.NoError(t, sessionRepo.Save(ctx, s))
	}

	err := sessionRepo.RevokeAllForUser(ctx, user.ID)
	require.NoError(t, err)

	active, err := sessionRepo.FindActiveByUserID(ctx, user.ID)
	require.NoError(t, err)
	assert.Empty(t, active, "all sessions should be revoked")
}

func TestSessionRepository_DeleteExpired(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	td := testhelpers.NewTestDatabase(t)
	ctx := context.Background()

	identityRepo := repository.NewPostgresIdentityRepository(td.DB)
	user := identity.NewUser("casdoor-id-006", "frank@example.com", "Frank", "org-1")
	require.NoError(t, identityRepo.Save(ctx, user))

	sessionRepo := repository.NewPostgresSessionRepository(td.DB)

	// Insert a session with an already-expired TTL (negative duration).
	expiredSess := session.NewSession(user.ID, "expired-sid", "at", "rt", "client", "127.0.0.1", "ua", -1*time.Hour)
	require.NoError(t, sessionRepo.Save(ctx, expiredSess))

	n, err := sessionRepo.DeleteExpired(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(1))
}
