// Package repository contains PostgreSQL implementations of domain repository interfaces.
package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/enterprise/sso-identity-hub/internal/domain/identity"
	"github.com/enterprise/sso-identity-hub/internal/infrastructure/database"
	apperrors "github.com/enterprise/sso-identity-hub/pkg/errors"
)

// userRow is the flat database representation of a User aggregate.
// Using a separate struct avoids leaking DB-specific types into the domain layer.
type userRow struct {
	ID             uuid.UUID      `db:"id"`
	CasdoorID      string         `db:"casdoor_id"`
	Email          string         `db:"email"`
	DisplayName    string         `db:"display_name"`
	AvatarURL      string         `db:"avatar_url"`
	OrganizationID string         `db:"organization_id"`
	Status         string         `db:"status"`
	MFAEnabled     bool           `db:"mfa_enabled"`
	MFAMethods     pq.StringArray `db:"mfa_methods"`
	ExternalIDs    []byte         `db:"external_ids"`
	LastLoginAt    *time.Time     `db:"last_login_at"`
	CreatedAt      time.Time      `db:"created_at"`
	UpdatedAt      time.Time      `db:"updated_at"`
}

// PostgresIdentityRepository implements identity.Repository against PostgreSQL.
type PostgresIdentityRepository struct {
	db *database.DB
}

// NewPostgresIdentityRepository constructs the repository with the shared DB pool.
func NewPostgresIdentityRepository(db *database.DB) *PostgresIdentityRepository {
	return &PostgresIdentityRepository{db: db}
}

func (r *PostgresIdentityRepository) FindByID(ctx context.Context, id uuid.UUID) (*identity.User, error) {
	var row userRow
	q := `SELECT * FROM sso_users WHERE id = $1 AND status != 'deleted'`
	if err := r.db.GetContext(ctx, &row, q, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("find user by id: %w", err)
	}
	return rowToUser(row)
}

func (r *PostgresIdentityRepository) FindByEmail(ctx context.Context, email string) (*identity.User, error) {
	var row userRow
	q := `SELECT * FROM sso_users WHERE email = $1 AND status != 'deleted'`
	if err := r.db.GetContext(ctx, &row, q, email); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("find user by email: %w", err)
	}
	return rowToUser(row)
}

func (r *PostgresIdentityRepository) FindByCasdoorID(ctx context.Context, casdoorID string) (*identity.User, error) {
	var row userRow
	q := `SELECT * FROM sso_users WHERE casdoor_id = $1 AND status != 'deleted'`
	if err := r.db.GetContext(ctx, &row, q, casdoorID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("find user by casdoor id: %w", err)
	}
	return rowToUser(row)
}

func (r *PostgresIdentityRepository) Save(ctx context.Context, user *identity.User) error {
	externalIDsJSON, err := json.Marshal(user.ExternalIDs)
	if err != nil {
		return fmt.Errorf("marshal external_ids: %w", err)
	}

	methods := make([]string, len(user.MFAMethods))
	for i, m := range user.MFAMethods {
		methods[i] = string(m)
	}

	q := `
		INSERT INTO sso_users
			(id, casdoor_id, email, display_name, avatar_url, organization_id,
			 status, mfa_enabled, mfa_methods, external_ids, last_login_at, created_at, updated_at)
		VALUES
			(:id, :casdoor_id, :email, :display_name, :avatar_url, :organization_id,
			 :status, :mfa_enabled, :mfa_methods, :external_ids, :last_login_at, :created_at, NOW())
		ON CONFLICT (id) DO UPDATE SET
			display_name    = EXCLUDED.display_name,
			avatar_url      = EXCLUDED.avatar_url,
			organization_id = EXCLUDED.organization_id,
			status          = EXCLUDED.status,
			mfa_enabled     = EXCLUDED.mfa_enabled,
			mfa_methods     = EXCLUDED.mfa_methods,
			external_ids    = EXCLUDED.external_ids,
			last_login_at   = EXCLUDED.last_login_at,
			updated_at      = NOW()
	`

	_, err = r.db.NamedExecContext(ctx, q, map[string]interface{}{
		"id":              user.ID,
		"casdoor_id":      user.CasdoorID,
		"email":           user.Email,
		"display_name":    user.DisplayName,
		"avatar_url":      user.AvatarURL,
		"organization_id": user.OrganizationID,
		"status":          string(user.Status),
		"mfa_enabled":     user.MFAEnabled,
		"mfa_methods":     pq.Array(methods),
		"external_ids":    externalIDsJSON,
		"last_login_at":   user.LastLoginAt,
		"created_at":      user.CreatedAt,
	})
	if err != nil {
		return fmt.Errorf("upsert user: %w", err)
	}
	return nil
}

func (r *PostgresIdentityRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status identity.Status) error {
	q := `UPDATE sso_users SET status = $1, updated_at = NOW() WHERE id = $2`
	if _, err := r.db.ExecContext(ctx, q, string(status), id); err != nil {
		return fmt.Errorf("update user status: %w", err)
	}
	return nil
}

func (r *PostgresIdentityRepository) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	q := `UPDATE sso_users SET last_login_at = NOW(), updated_at = NOW() WHERE id = $1`
	if _, err := r.db.ExecContext(ctx, q, id); err != nil {
		return fmt.Errorf("update last login: %w", err)
	}
	return nil
}

func (r *PostgresIdentityRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.UpdateStatus(ctx, id, identity.StatusDeleted)
}

// rowToUser converts a flat DB row into the User aggregate.
func rowToUser(row userRow) (*identity.User, error) {
	var externalIDs map[string]string
	if err := json.Unmarshal(row.ExternalIDs, &externalIDs); err != nil {
		externalIDs = make(map[string]string)
	}

	methods := make([]identity.MFAMethod, len(row.MFAMethods))
	for i, m := range row.MFAMethods {
		methods[i] = identity.MFAMethod(m)
	}

	return &identity.User{
		ID:             row.ID,
		CasdoorID:      row.CasdoorID,
		Email:          row.Email,
		DisplayName:    row.DisplayName,
		AvatarURL:      row.AvatarURL,
		OrganizationID: row.OrganizationID,
		Status:         identity.Status(row.Status),
		MFAEnabled:     row.MFAEnabled,
		MFAMethods:     methods,
		ExternalIDs:    externalIDs,
		LastLoginAt:    row.LastLoginAt,
		CreatedAt:      row.CreatedAt,
		UpdatedAt:      row.UpdatedAt,
	}, nil
}
