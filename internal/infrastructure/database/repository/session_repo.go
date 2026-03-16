package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/enterprise/sso-identity-hub/internal/domain/session"
	"github.com/enterprise/sso-identity-hub/internal/infrastructure/database"
	apperrors "github.com/enterprise/sso-identity-hub/pkg/errors"
)

type sessionRow struct {
	ID           uuid.UUID  `db:"id"`
	UserID       uuid.UUID  `db:"user_id"`
	SID          string     `db:"sid"`
	AccessToken  string     `db:"access_token"`
	RefreshToken string     `db:"refresh_token"`
	ClientID     string     `db:"client_id"`
	IPAddress    string     `db:"ip_address"`
	UserAgent    string     `db:"user_agent"`
	State        string     `db:"state"`
	ExpiresAt    time.Time  `db:"expires_at"`
	CreatedAt    time.Time  `db:"created_at"`
	RevokedAt    *time.Time `db:"revoked_at"`
}

// PostgresSessionRepository implements session.Repository against PostgreSQL.
type PostgresSessionRepository struct {
	db *database.DB
}

func NewPostgresSessionRepository(db *database.DB) *PostgresSessionRepository {
	return &PostgresSessionRepository{db: db}
}

func (r *PostgresSessionRepository) Save(ctx context.Context, s *session.Session) error {
	q := `
		INSERT INTO sso_sessions
			(id, user_id, sid, access_token, refresh_token, client_id, ip_address, user_agent, state, expires_at, created_at)
		VALUES
			(:id, :user_id, :sid, :access_token, :refresh_token, :client_id, :ip_address, :user_agent, :state, :expires_at, :created_at)
	`
	_, err := r.db.NamedExecContext(ctx, q, map[string]interface{}{
		"id":            s.ID,
		"user_id":       s.UserID,
		"sid":           s.SID,
		"access_token":  s.AccessToken,
		"refresh_token": s.RefreshToken,
		"client_id":     s.ClientID,
		"ip_address":    s.IPAddress,
		"user_agent":    s.UserAgent,
		"state":         string(s.State),
		"expires_at":    s.ExpiresAt,
		"created_at":    s.CreatedAt,
	})
	if err != nil {
		return fmt.Errorf("save session: %w", err)
	}
	return nil
}

func (r *PostgresSessionRepository) FindByID(ctx context.Context, id uuid.UUID) (*session.Session, error) {
	var row sessionRow
	q := `SELECT * FROM sso_sessions WHERE id = $1`
	if err := r.db.GetContext(ctx, &row, q, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("find session by id: %w", err)
	}
	return rowToSession(row), nil
}

func (r *PostgresSessionRepository) FindBySID(ctx context.Context, sid string) (*session.Session, error) {
	var row sessionRow
	q := `SELECT * FROM sso_sessions WHERE sid = $1`
	if err := r.db.GetContext(ctx, &row, q, sid); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("find session by sid: %w", err)
	}
	return rowToSession(row), nil
}

func (r *PostgresSessionRepository) FindActiveByUserID(ctx context.Context, userID uuid.UUID) ([]*session.Session, error) {
	var rows []sessionRow
	q := `SELECT * FROM sso_sessions WHERE user_id = $1 AND state = 'active' AND expires_at > NOW()`
	if err := r.db.SelectContext(ctx, &rows, q, userID); err != nil {
		return nil, fmt.Errorf("find active sessions by user: %w", err)
	}

	sessions := make([]*session.Session, len(rows))
	for i, row := range rows {
		sessions[i] = rowToSession(row)
	}
	return sessions, nil
}

func (r *PostgresSessionRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	q := `UPDATE sso_sessions SET state = 'revoked', revoked_at = NOW() WHERE id = $1`
	if _, err := r.db.ExecContext(ctx, q, id); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

func (r *PostgresSessionRepository) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	q := `UPDATE sso_sessions SET state = 'revoked', revoked_at = NOW() WHERE user_id = $1 AND state = 'active'`
	if _, err := r.db.ExecContext(ctx, q, userID); err != nil {
		return fmt.Errorf("revoke all user sessions: %w", err)
	}
	return nil
}

func (r *PostgresSessionRepository) DeleteExpired(ctx context.Context) (int64, error) {
	q := `DELETE FROM sso_sessions WHERE expires_at < NOW() AND state != 'revoked'`
	result, err := r.db.ExecContext(ctx, q)
	if err != nil {
		return 0, fmt.Errorf("delete expired sessions: %w", err)
	}
	n, _ := result.RowsAffected()
	return n, nil
}

func rowToSession(row sessionRow) *session.Session {
	return &session.Session{
		ID:           row.ID,
		UserID:       row.UserID,
		SID:          row.SID,
		AccessToken:  row.AccessToken,
		RefreshToken: row.RefreshToken,
		ClientID:     row.ClientID,
		IPAddress:    row.IPAddress,
		UserAgent:    row.UserAgent,
		State:        session.State(row.State),
		ExpiresAt:    row.ExpiresAt,
		CreatedAt:    row.CreatedAt,
		RevokedAt:    row.RevokedAt,
	}
}
