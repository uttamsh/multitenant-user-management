// seed-dev provisions an explicit development fixture. It is never run by API startup.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/uttam/multitenant-user-management/internal/config"
	"github.com/uttam/multitenant-user-management/internal/database"
	"golang.org/x/crypto/bcrypt"
)

const devPassword = "DevOnly-ChangeMe-2026!"

func main() {
	development := flag.Bool("development", false, "confirm this is a development database")
	flag.Parse()
	if !*development {
		fmt.Fprintln(os.Stderr, "refusing to seed: pass --development only for a development database")
		os.Exit(1)
	}
	if err := seed(); err != nil {
		// Driver errors can contain credentials; report a fixed diagnostic only.
		fmt.Fprintln(os.Stderr, "development seed failed; check database access and conflicting dev-auth fixtures (existing credentials are never overwritten)")
		os.Exit(1)
	}
	fmt.Println("Development fixture ready: tenant dev-auth, email dev-auth@example.test. See README for the development-only password.")
}

func seed() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, cfg.DatabaseURL, cfg.DBMaxConns, cfg.DBTimeout)
	if err != nil {
		return err
	}
	defer pool.Close()
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		_ = tx.Rollback(cleanup)
	}()
	// A transaction-level lock makes concurrent invocations idempotent too.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(726031901)`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO tenants (name, code) VALUES ('Development Auth Only', 'dev-auth') ON CONFLICT (code) DO NOTHING`); err != nil {
		return err
	}
	var tenantID string
	if err := tx.QueryRow(ctx, `SELECT id::text FROM tenants WHERE code='dev-auth' AND name='Development Auth Only' AND status='active' FOR SHARE`).Scan(&tenantID); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(devPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO users (email, full_name, password_hash) VALUES ('dev-auth@example.test', 'Development Auth Only', $1) ON CONFLICT DO NOTHING`, string(hash)); err != nil {
		return err
	}
	var userID, existingHash string
	if err := tx.QueryRow(ctx, `SELECT id::text, password_hash FROM users WHERE LOWER(email)='dev-auth@example.test' AND full_name='Development Auth Only' AND deleted_at IS NULL FOR SHARE`).Scan(&userID, &existingHash); err != nil {
		return err
	}
	if bcrypt.CompareHashAndPassword([]byte(existingHash), []byte(devPassword)) != nil {
		return errors.New("conflicting development account")
	}
	if _, err := tx.Exec(ctx, `INSERT INTO tenant_users (tenant_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, tenantID, userID); err != nil {
		return err
	}
	var active bool
	if err := tx.QueryRow(ctx, `SELECT status='active' FROM tenant_users WHERE tenant_id=$1 AND user_id=$2 FOR SHARE`, tenantID, userID).Scan(&active); err != nil {
		return err
	}
	if !active {
		return errors.New("development membership is suspended")
	}
	return tx.Commit(ctx)
}
