// Package database manages the PostgreSQL connection pool and schema migrations.
package database

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/enterprise/sso-identity-hub/internal/config"
)

// DB wraps sqlx.DB with project-specific helpers.
type DB struct {
	*sqlx.DB
}

// Connect opens a connection pool to PostgreSQL and verifies connectivity.
// Pool parameters are taken from config to match the expected load profile.
func Connect(cfg config.PostgresConfig) (*DB, error) {
	db, err := sqlx.Open("postgres", cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("open postgres connection: %w", err)
	}

	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	return &DB{db}, nil
}

// RunMigrations applies all pending schema migrations from the given file path.
// Using migrate here (instead of init scripts) ensures atomic, versioned schema evolution.
func RunMigrations(dsn, migrationsPath string) error {
	m, err := migrate.New("file://"+migrationsPath, dsn)
	if err != nil {
		return fmt.Errorf("create migrator: %w", err)
	}
	defer m.Close()

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("run migrations: %w", err)
	}

	return nil
}

// HealthCheck performs a lightweight query to confirm the database is reachable.
// Intended for use by the /healthz handler.
func (db *DB) HealthCheck(ctx context.Context) error {
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("postgres health check failed: %w", err)
	}
	return nil
}
