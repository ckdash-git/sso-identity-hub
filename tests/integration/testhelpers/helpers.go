// Package testhelpers provides shared test infrastructure for integration tests.
// It uses testcontainers-go to spin up a real PostgreSQL instance so that
// repository tests exercise actual SQL semantics (constraints, transactions, indexes).
package testhelpers

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/enterprise/sso-identity-hub/internal/config"
	"github.com/enterprise/sso-identity-hub/internal/infrastructure/database"
)

// TestDatabase holds a running PostgreSQL container and the connected DB pool.
type TestDatabase struct {
	DB        *database.DB
	Container testcontainers.Container
	DSN       string
}

// NewTestDatabase starts a PostgreSQL container, runs migrations, and returns a
// ready-to-use database handle. It registers cleanup via t.Cleanup so the
// container is always stopped when the test finishes.
func NewTestDatabase(t *testing.T) *TestDatabase {
	t.Helper()
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "sso_test",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err, "start postgres container")

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "5432")
	require.NoError(t, err)

	dsn := fmt.Sprintf(
		"host=%s port=%s user=test password=test dbname=sso_test sslmode=disable",
		host, port.Port(),
	)

	// Wait for the DSN to become connectable (container may report ready before TCP accepts).
	var db *database.DB
	for i := 0; i < 10; i++ {
		db, err = database.Connect(config.PostgresConfig{
			Host:            host,
			Port:            int(port.Int()),
			User:            "test",
			Password:        "test",
			Database:        "sso_test",
			SSLMode:         "disable",
			MaxOpenConns:    5,
			MaxIdleConns:    2,
			ConnMaxLifetime: 5 * time.Minute,
		})
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	require.NoError(t, err, "connect to test postgres")

	err = database.RunMigrations(dsn, "../../migrations")
	require.NoError(t, err, "run test migrations")

	t.Cleanup(func() {
		_ = container.Terminate(ctx)
	})

	return &TestDatabase{DB: db, Container: container, DSN: dsn}
}

// TruncateTables removes all rows from the given tables between tests.
// This is faster than re-running migrations for every test case.
func TruncateTables(t *testing.T, db *sqlx.DB, tables ...string) {
	t.Helper()
	for _, table := range tables {
		_, err := db.Exec(fmt.Sprintf("TRUNCATE TABLE %s CASCADE", table))
		require.NoError(t, err, "truncate %s", table)
	}
}
