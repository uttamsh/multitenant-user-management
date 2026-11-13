package database

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Open creates a pool and verifies connectivity before returning it.
// Connection errors intentionally omit the DSN and driver details.
func Open(ctx context.Context, url string, maxConns int32, timeout time.Duration) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, errors.New("invalid database configuration")
	}
	cfg.MaxConns = maxConns
	cfg.ConnConfig.ConnectTimeout = timeout
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, errors.New("could not create database pool")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, errors.New("database startup check failed")
	}
	return pool, nil
}
