// Package storetest creates throw-away PostgreSQL databases for tests.
package storetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/monirujjaman-dev/server-manager/internal/server/store"
)

// EnvVar names the variable holding an admin connection URL (postgres://...) for a
// server where the user may create databases. Tests are skipped when it is unset.
const EnvVar = "SM_TEST_DATABASE_URL"

// NewDatabase creates a fresh database, applies all migrations and returns its URL.
// The database is dropped when the test ends, so tests in different packages can run
// in parallel without sharing state.
func NewDatabase(t testing.TB) string {
	t.Helper()
	admin := os.Getenv(EnvVar)
	if admin == "" {
		t.Skip(EnvVar + " not set")
	}
	u, err := url.Parse(admin)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		t.Fatalf("%s must be a postgres:// URL", EnvVar)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "sm_test_" + hex.EncodeToString(b)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatalf("connect to %s: %v", EnvVar, err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create test database: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c, err := pgx.Connect(ctx, admin)
		if err != nil {
			t.Logf("drop test database: %v", err)
			return
		}
		defer func() { _ = c.Close(context.Background()) }()
		if _, err := c.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			t.Logf("drop test database: %v", err)
		}
	})

	u.Path = "/" + name
	dbURL := u.String()
	m, err := store.NewMigrator(dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	if _, err := m.Up(ctx); err != nil {
		t.Fatalf("migrate test database: %v", err)
	}
	return dbURL
}

// Open returns a Store on a fresh database, closed when the test ends.
func Open(t testing.TB) (*store.Store, string) {
	t.Helper()
	dbURL := NewDatabase(t)
	s, err := store.Open(context.Background(), dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, dbURL
}
