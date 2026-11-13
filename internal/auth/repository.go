package auth

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct{ pool *pgxpool.Pool }

func NewRepository(pool *pgxpool.Pool) *PostgresRepository { return &PostgresRepository{pool: pool} }

const activeJoin = ` JOIN users u ON u.id = tu.user_id
 JOIN tenants t ON t.id = tu.tenant_id `
const activeWhere = ` u.deleted_at IS NULL AND t.status = 'active' AND tu.status = 'active' `

func (r *PostgresRepository) FindCredentials(ctx context.Context, email, tenantCode string) (Credentials, error) {
	var c Credentials
	err := r.pool.QueryRow(ctx, `SELECT u.id::text, t.id::text, u.password_hash FROM tenant_users tu`+activeJoin+
		`WHERE LOWER(u.email) = LOWER($1) AND t.code = $2 AND `+activeWhere, email, tenantCode).Scan(&c.UserID, &c.TenantID, &c.PasswordHash)
	return c, repositoryError(err)
}

func (r *PostgresRepository) CreateSession(ctx context.Context, id Identity, session RefreshSession) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	var exists int
	// Lock validity rows until commit so suspension/deletion cannot race issuance.
	err = tx.QueryRow(ctx, `SELECT 1 FROM tenant_users tu`+activeJoin+
		`WHERE u.id = $1 AND t.id = $2 AND `+activeWhere+`FOR SHARE OF u, t, tu`, id.UserID, id.TenantID).Scan(&exists)
	if err != nil {
		return repositoryError(err)
	}
	if err := insertSession(ctx, tx, id, session); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *PostgresRepository) Rotate(ctx context.Context, hash string, issue func(Identity) (RefreshSession, error)) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	var id Identity
	err = tx.QueryRow(ctx, `SELECT u.id::text, t.id::text FROM refresh_tokens rt
 JOIN tenant_users tu ON tu.user_id = rt.user_id AND tu.tenant_id = rt.tenant_id`+activeJoin+
		`WHERE rt.token_hash = $1 AND rt.revoked_at IS NULL AND rt.expires_at > clock_timestamp() AND `+activeWhere+
		`FOR UPDATE OF rt FOR SHARE OF u, t, tu`, hash).Scan(&id.UserID, &id.TenantID)
	if err != nil {
		return repositoryError(err)
	}
	session, err := issue(id)
	if err != nil {
		return err
	}
	// Recheck expiry after waiting for locks and generating credentials.
	tag, err := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = clock_timestamp()
 WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > clock_timestamp()`, hash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrUnauthorized
	}
	if err = insertSession(ctx, tx, id, session); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func insertSession(ctx context.Context, tx pgx.Tx, id Identity, s RefreshSession) error {
	_, err := tx.Exec(ctx, `INSERT INTO refresh_tokens (user_id, tenant_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)`, id.UserID, id.TenantID, s.Hash, s.ExpiresAt)
	return err
}

func (r *PostgresRepository) Revoke(ctx context.Context, hash string) error {
	// Atomic update serializes with rotation on the same token row. A token
	// rotated or revoked first cannot subsequently authenticate logout.
	tag, err := r.pool.Exec(ctx, `UPDATE refresh_tokens rt SET revoked_at = clock_timestamp()
 FROM tenant_users tu, users u, tenants t
 WHERE rt.token_hash = $1 AND rt.revoked_at IS NULL AND rt.expires_at > clock_timestamp()
 AND tu.user_id = rt.user_id AND tu.tenant_id = rt.tenant_id
 AND u.id = tu.user_id AND t.id = tu.tenant_id AND `+activeWhere, hash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrUnauthorized
	}
	return nil
}

func (r *PostgresRepository) Audit(ctx context.Context, action string, id *Identity) error {
	var userID, tenantID any
	if id != nil {
		userID, tenantID = id.UserID, id.TenantID
	}
	_, err := r.pool.Exec(ctx, `INSERT INTO audit_logs (action, actor_id, tenant_id) VALUES ($1, $2, $3)`, action, userID, tenantID)
	return err
}

func repositoryError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrUnauthorized
	}
	return err
}

func rollback(tx pgx.Tx) {
	// Rollback must still release the transaction when the request was canceled.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
