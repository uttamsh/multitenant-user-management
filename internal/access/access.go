// Package access defines authorization boundaries and scoped transactions.
package access

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/uttam/multitenant-user-management/internal/auth"
)

var (
	ErrInvalid  = errors.New("invalid request")
	ErrNotFound = errors.New("resource not found")
	ErrConflict = errors.New("resource conflict or stale version")
)

type Policy interface {
	Check(context.Context, auth.Identity, string) error
}

// DenyAll remains a safe fallback when no permission evaluator is configured.
type DenyAll struct{}

func (DenyAll) Check(context.Context, auth.Identity, string) error { return auth.ErrForbidden }

type TransactionPolicy interface {
	CheckTx(context.Context, pgx.Tx, auth.Identity, string) error
}

type TargetPolicy interface {
	CheckTargetTx(context.Context, pgx.Tx, auth.Identity, string, string) error
}

// CheckTarget protects operations that can transfer control of an identity or
// reactivate dormant grants. Call only after a tenant-scoped target lookup.
func CheckTarget(ctx context.Context, tx pgx.Tx, id auth.Identity, targetID, operation string) error {
	if req, ok := ctx.Value(requirementKey{}).(requirement); ok {
		if policy, ok := req.policy.(TargetPolicy); ok {
			return policy.CheckTargetTx(ctx, tx, id, targetID, operation)
		}
	}
	return nil
}

type requirementKey struct{}
type requirement struct {
	policy Policy
	action string
}

// Bind carries the checked requirement to the repository. Database policies are
// rechecked after taking the tenant lock, closing the check/use revocation race.
func Bind(ctx context.Context, policy Policy, action string) context.Context {
	return context.WithValue(ctx, requirementKey{}, requirement{policy, action})
}

func Check(ctx context.Context, policy Policy, id auth.Identity, action string) error {
	if !UUID(id.UserID) || !UUID(id.TenantID) {
		return auth.ErrUnauthorized
	}
	if policy == nil {
		return auth.ErrForbidden
	}
	return policy.Check(ctx, id, action)
}

func UUID(value string) bool {
	var id pgtype.UUID
	return len(value) == 36 && id.Scan(value) == nil && id.Valid && id.Bytes != [16]byte{}
}

func Status(value string) bool { return value == "active" || value == "suspended" }

func DBError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505", "23503", "40001", "40P01":
			return ErrConflict
		case "22P02", "23514", "22001":
			return ErrInvalid
		}
	}
	return err
}

func Rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

// Scoped serializes management writes per tenant, locks out suspension while
// reading, and rechecks the actor against current database state. Target user
// rows are additionally locked by repositories to serialize cross-tenant edits.
func Scoped(ctx context.Context, pool *pgxpool.Pool, id auth.Identity, write, allowSuspended bool, fn func(pgx.Tx) error) error {
	if !UUID(id.UserID) || !UUID(id.TenantID) {
		return auth.ErrUnauthorized
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer Rollback(tx)
	lock := " FOR SHARE"
	if write {
		lock = " FOR UPDATE"
	}
	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM tenants WHERE id=$1`+lock, id.TenantID).Scan(&status); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return auth.ErrForbidden
		}
		return DBError(err)
	}
	if status != "active" && !allowSuspended {
		return auth.ErrForbidden
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenant_users tu JOIN users u ON u.id=tu.user_id
 WHERE tu.tenant_id=$1 AND tu.user_id=$2 AND tu.status='active' AND tu.removed_at IS NULL AND u.deleted_at IS NULL)`, id.TenantID, id.UserID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return auth.ErrForbidden
	}
	if req, ok := ctx.Value(requirementKey{}).(requirement); ok {
		if policy, ok := req.policy.(TransactionPolicy); ok {
			if err := policy.CheckTx(ctx, tx, id, req.action); err != nil {
				return err
			}
		}
	}
	if err := fn(tx); err != nil {
		return DBError(err)
	}
	return DBError(tx.Commit(ctx))
}

// Audit is part of the mutation transaction: failed audits roll back the change.
// Metadata deliberately omits profiles, passwords and submitted request bodies.
func Audit(ctx context.Context, tx pgx.Tx, id auth.Identity, action, targetType, targetID string) error {
	_, err := tx.Exec(ctx, `INSERT INTO audit_logs(tenant_id,actor_id,action,target_type,target_id) VALUES($1,$2,$3,$4,$5)`, id.TenantID, id.UserID, action, targetType, targetID)
	return err
}
