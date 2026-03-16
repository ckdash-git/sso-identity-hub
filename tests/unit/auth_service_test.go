package unit_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/enterprise/sso-identity-hub/internal/domain/identity"
	"github.com/enterprise/sso-identity-hub/internal/domain/session"
	apperrors "github.com/enterprise/sso-identity-hub/pkg/errors"
)

// ---------------------------------------------------------------------------
// Mock: identity.Repository
// ---------------------------------------------------------------------------

type mockIdentityRepo struct{ mock.Mock }

func (m *mockIdentityRepo) FindByID(ctx context.Context, id uuid.UUID) (*identity.User, error) {
	args := m.Called(ctx, id)
	if u := args.Get(0); u != nil {
		return u.(*identity.User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockIdentityRepo) FindByEmail(ctx context.Context, email string) (*identity.User, error) {
	args := m.Called(ctx, email)
	if u := args.Get(0); u != nil {
		return u.(*identity.User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockIdentityRepo) FindByCasdoorID(ctx context.Context, casdoorID string) (*identity.User, error) {
	args := m.Called(ctx, casdoorID)
	if u := args.Get(0); u != nil {
		return u.(*identity.User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockIdentityRepo) Save(ctx context.Context, user *identity.User) error {
	return m.Called(ctx, user).Error(0)
}

func (m *mockIdentityRepo) UpdateStatus(ctx context.Context, id uuid.UUID, status identity.Status) error {
	return m.Called(ctx, id, status).Error(0)
}

func (m *mockIdentityRepo) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockIdentityRepo) Delete(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

// ---------------------------------------------------------------------------
// Tests: identity.Service
// ---------------------------------------------------------------------------

func TestIdentityService_ProvisionUser_CreatesNewUser(t *testing.T) {
	repo := new(mockIdentityRepo)
	svc := identity.NewService(repo)
	ctx := context.Background()

	casdoorID := "csd-new-user"

	// Simulate user not found — triggers creation path.
	repo.On("FindByCasdoorID", ctx, casdoorID).Return(nil, apperrors.ErrNotFound)
	repo.On("Save", ctx, mock.AnythingOfType("*identity.User")).Return(nil)

	user, err := svc.ProvisionUser(ctx, casdoorID, "new@example.com", "New User", "org1")
	require.NoError(t, err)
	assert.Equal(t, casdoorID, user.CasdoorID)
	assert.Equal(t, "new@example.com", user.Email)
	assert.Equal(t, identity.StatusActive, user.Status)

	repo.AssertExpectations(t)
}

func TestIdentityService_ProvisionUser_UpdatesExistingUser(t *testing.T) {
	repo := new(mockIdentityRepo)
	svc := identity.NewService(repo)
	ctx := context.Background()

	existing := &identity.User{
		ID:          uuid.New(),
		CasdoorID:   "csd-existing",
		Email:       "existing@example.com",
		DisplayName: "Old Name",
		Status:      identity.StatusActive,
	}

	repo.On("FindByCasdoorID", ctx, "csd-existing").Return(existing, nil)
	repo.On("Save", ctx, mock.AnythingOfType("*identity.User")).Return(nil)

	user, err := svc.ProvisionUser(ctx, "csd-existing", "existing@example.com", "New Name", "org1")
	require.NoError(t, err)
	assert.Equal(t, "New Name", user.DisplayName)

	repo.AssertExpectations(t)
}

func TestIdentityService_SuspendUser(t *testing.T) {
	repo := new(mockIdentityRepo)
	svc := identity.NewService(repo)
	ctx := context.Background()
	userID := uuid.New()

	repo.On("UpdateStatus", ctx, userID, identity.StatusSuspended).Return(nil)

	err := svc.SuspendUser(ctx, userID)
	require.NoError(t, err)
	repo.AssertExpectations(t)
}

func TestIdentityService_SuspendUser_ReturnsInternalErrorOnDBFailure(t *testing.T) {
	repo := new(mockIdentityRepo)
	svc := identity.NewService(repo)
	ctx := context.Background()
	userID := uuid.New()

	repo.On("UpdateStatus", ctx, userID, identity.StatusSuspended).
		Return(errors.New("db connection lost"))

	err := svc.SuspendUser(ctx, userID)
	require.Error(t, err)
	assert.True(t, errors.Is(err, apperrors.ErrInternal))
}

// ---------------------------------------------------------------------------
// Mock: session.Repository
// ---------------------------------------------------------------------------

type mockSessionRepo struct{ mock.Mock }

func (m *mockSessionRepo) Save(ctx context.Context, s *session.Session) error {
	return m.Called(ctx, s).Error(0)
}

func (m *mockSessionRepo) FindByID(ctx context.Context, id uuid.UUID) (*session.Session, error) {
	args := m.Called(ctx, id)
	if s := args.Get(0); s != nil {
		return s.(*session.Session), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockSessionRepo) FindBySID(ctx context.Context, sid string) (*session.Session, error) {
	args := m.Called(ctx, sid)
	if s := args.Get(0); s != nil {
		return s.(*session.Session), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockSessionRepo) FindActiveByUserID(ctx context.Context, userID uuid.UUID) ([]*session.Session, error) {
	args := m.Called(ctx, userID)
	if s := args.Get(0); s != nil {
		return s.([]*session.Session), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockSessionRepo) Revoke(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}

func (m *mockSessionRepo) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	return m.Called(ctx, userID).Error(0)
}

func (m *mockSessionRepo) DeleteExpired(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

// ---------------------------------------------------------------------------
// Tests: session.Service
// ---------------------------------------------------------------------------

func TestSessionService_CreateSession(t *testing.T) {
	repo := new(mockSessionRepo)
	svc := session.NewService(repo, 8*time.Hour)
	ctx := context.Background()

	userID := uuid.New()
	repo.On("Save", ctx, mock.AnythingOfType("*session.Session")).Return(nil)

	sess, err := svc.CreateSession(ctx, userID, "sid-1", "at-1", "rt-1", "client-1", "127.0.0.1", "test-ua")
	require.NoError(t, err)
	assert.Equal(t, userID, sess.UserID)
	assert.Equal(t, session.StateActive, sess.State)
	assert.Equal(t, "sid-1", sess.SID)
	assert.WithinDuration(t, time.Now().Add(8*time.Hour), sess.ExpiresAt, 5*time.Second)

	repo.AssertExpectations(t)
}

func TestSessionService_ValidateSession_ReturnsExpiredError(t *testing.T) {
	repo := new(mockSessionRepo)
	svc := session.NewService(repo, 8*time.Hour)
	ctx := context.Background()

	expiredSession := &session.Session{
		ID:        uuid.New(),
		State:     session.StateActive,
		ExpiresAt: time.Now().Add(-1 * time.Hour), // already expired
	}

	repo.On("FindByID", ctx, expiredSession.ID).Return(expiredSession, nil)

	_, err := svc.ValidateSession(ctx, expiredSession.ID)
	require.Error(t, err)
	assert.True(t, errors.Is(err, apperrors.ErrSessionExpired))
}

func TestSessionService_RevokeSession_IdempotentOnAlreadyRevoked(t *testing.T) {
	repo := new(mockSessionRepo)
	svc := session.NewService(repo, 8*time.Hour)
	ctx := context.Background()

	alreadyRevoked := &session.Session{
		ID:    uuid.New(),
		State: session.StateRevoked,
	}

	repo.On("FindByID", ctx, alreadyRevoked.ID).Return(alreadyRevoked, nil)
	// Revoke should NOT be called on the repo because session is already revoked.

	err := svc.RevokeSession(ctx, alreadyRevoked.ID)
	require.NoError(t, err)
	repo.AssertNotCalled(t, "Revoke")
}

func TestSessionService_RevokeAllUserSessions_ReturnsActiveSessions(t *testing.T) {
	repo := new(mockSessionRepo)
	svc := session.NewService(repo, 8*time.Hour)
	ctx := context.Background()

	userID := uuid.New()
	active := []*session.Session{
		{ID: uuid.New(), UserID: userID, State: session.StateActive, ExpiresAt: time.Now().Add(1 * time.Hour)},
		{ID: uuid.New(), UserID: userID, State: session.StateActive, ExpiresAt: time.Now().Add(2 * time.Hour)},
	}

	repo.On("FindActiveByUserID", ctx, userID).Return(active, nil)
	repo.On("RevokeAllForUser", ctx, userID).Return(nil)

	revoked, err := svc.RevokeAllUserSessions(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, revoked, 2)

	repo.AssertExpectations(t)
}
