// Package store owns the control plane's PostgreSQL schema and data access.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/monirujjaman-dev/server-manager/internal/server/store/db"
)

// Store wraps a connection pool and the sqlc-generated queries.
type Store struct {
	Pool *pgxpool.Pool
	*db.Queries
}

// Open connects to PostgreSQL and verifies the connection.
func Open(ctx context.Context, databaseURL string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}
	cfg.MaxConnIdleTime = 5 * time.Minute
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	return &Store{Pool: pool, Queries: db.New(pool)}, nil
}

// Close releases all connections.
func (s *Store) Close() { s.Pool.Close() }
