package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migrator applies the embedded schema migrations.
type Migrator struct {
	db       *sql.DB
	provider *goose.Provider
}

// NewMigrator opens a dedicated connection for migrations.
func NewMigrator(databaseURL string) (*Migrator, error) {
	cfg, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}
	sqlDB := stdlib.OpenDB(*cfg)
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return nil, err
	}
	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, sub)
	if err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	return &Migrator{db: sqlDB, provider: p}, nil
}

// Up applies all pending migrations and returns how many were applied.
func (m *Migrator) Up(ctx context.Context) (int, error) {
	res, err := m.provider.Up(ctx)
	return len(res), err
}

// Down rolls back the most recent migration.
func (m *Migrator) Down(ctx context.Context) error {
	_, err := m.provider.Down(ctx)
	return err
}

// DownTo rolls back to version (0 removes everything).
func (m *Migrator) DownTo(ctx context.Context, version int64) error {
	_, err := m.provider.DownTo(ctx, version)
	return err
}

// MigrationStatus describes one migration.
type MigrationStatus struct {
	Version int64
	Name    string
	Applied bool
}

// Status lists all known migrations and whether they are applied.
func (m *Migrator) Status(ctx context.Context) ([]MigrationStatus, error) {
	st, err := m.provider.Status(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]MigrationStatus, 0, len(st))
	for _, s := range st {
		out = append(out, MigrationStatus{
			Version: s.Source.Version,
			Name:    s.Source.Path,
			Applied: s.State == goose.StateApplied,
		})
	}
	return out, nil
}

// Close releases the migration connection.
func (m *Migrator) Close() error { return m.db.Close() }
