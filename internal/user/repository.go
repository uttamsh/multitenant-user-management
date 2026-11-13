package user

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/uttam/multitenant-user-management/internal/access"
	"github.com/uttam/multitenant-user-management/internal/auth"
)

type PostgresRepository struct{ pool *pgxpool.Pool }

func NewRepository(pool *pgxpool.Pool) *PostgresRepository { return &PostgresRepository{pool} }

const userColumns = `u.id::text,u.email,u.full_name,u.created_at,u.updated_at,tu.status,tu.joined_at,tu.updated_at`
const scopedFrom = ` FROM users u JOIN tenant_users tu ON tu.user_id=u.id WHERE tu.tenant_id=$1 AND tu.removed_at IS NULL AND u.deleted_at IS NULL `

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.FullName, &u.CreatedAt, &u.UpdatedAt, &u.Membership.Status, &u.Membership.JoinedAt, &u.Membership.UpdatedAt)
	u.Membership.UserID = u.ID
	return u, access.DBError(err)
}
func get(ctx context.Context, tx pgx.Tx, id auth.Identity, userID string, lock bool) (User, error) {
	suffix := ""
	if lock {
		suffix = " FOR NO KEY UPDATE OF u"
	}
	return scanUser(tx.QueryRow(ctx, `SELECT `+userColumns+scopedFrom+`AND u.id=$2`+suffix, id.TenantID, userID))
}

func (r *PostgresRepository) Create(ctx context.Context, id auth.Identity, req CreateRequest, hash string) (User, error) {
	var u User
	err := access.Scoped(ctx, r.pool, id, true, false, func(tx pgx.Tx) error {
		var userID string
		if err := tx.QueryRow(ctx, `INSERT INTO users(email,full_name,password_hash) VALUES(LOWER($1),$2,$3) RETURNING id::text`, req.Email, req.FullName, hash).Scan(&userID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO tenant_users(tenant_id,user_id) VALUES($1,$2)`, id.TenantID, userID); err != nil {
			return err
		}
		var err error
		u, err = get(ctx, tx, id, userID, false)
		if err != nil {
			return err
		}
		if err := access.Audit(ctx, tx, id, "user.create", "user", userID); err != nil {
			return err
		}
		return access.Audit(ctx, tx, id, "membership.create", "user", userID)
	})
	return u, err
}
func (r *PostgresRepository) Get(ctx context.Context, id auth.Identity, userID string) (User, error) {
	var u User
	err := access.Scoped(ctx, r.pool, id, false, false, func(tx pgx.Tx) error { var err error; u, err = get(ctx, tx, id, userID, false); return err })
	return u, err
}
func (r *PostgresRepository) List(ctx context.Context, id auth.Identity, q ListQuery) (Page, error) {
	p := Page{Items: []User{}, Page: q.Page, PageSize: q.PageSize}
	err := access.Scoped(ctx, r.pool, id, false, false, func(tx pgx.Tx) error {
		filter := scopedFrom + `AND ($2='' OR strpos(LOWER(u.email),LOWER($2))>0 OR strpos(LOWER(u.full_name),LOWER($2))>0) AND ($3='' OR tu.status=$3)`
		if err := tx.QueryRow(ctx, `SELECT count(*)`+filter, id.TenantID, q.Search, q.MembershipStatus).Scan(&p.Total); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+userColumns+filter+` ORDER BY u.created_at,u.id LIMIT $4 OFFSET $5`, id.TenantID, q.Search, q.MembershipStatus, q.PageSize, (q.Page-1)*q.PageSize)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			u, err := scanUser(rows)
			if err != nil {
				return err
			}
			p.Items = append(p.Items, u)
		}
		return rows.Err()
	})
	return p, err
}

// Global profile mutations are forbidden while another tenant retains a live
// membership (even suspended), so one tenant cannot alter another's identity.
func exclusivelyOwned(ctx context.Context, tx pgx.Tx, id auth.Identity, userID string) error {
	var shared bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenant_users WHERE user_id=$1 AND tenant_id<>$2 AND removed_at IS NULL)`, userID, id.TenantID).Scan(&shared)
	if err != nil {
		return err
	}
	if shared {
		return access.ErrConflict
	}
	return nil
}
func revoke(ctx context.Context, tx pgx.Tx, tenantID, userID string) error {
	_, err := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND user_id=$2 AND revoked_at IS NULL`, tenantID, userID)
	return err
}

func (r *PostgresRepository) Update(ctx context.Context, id auth.Identity, userID string, req UpdateRequest, hash *string) (User, error) {
	var u User
	err := access.Scoped(ctx, r.pool, id, true, false, func(tx pgx.Tx) error {
		old, err := get(ctx, tx, id, userID, true)
		if err != nil {
			return err
		}
		if !old.UpdatedAt.Equal(req.ExpectedUpdatedAt) {
			return access.ErrConflict
		}
		if err := exclusivelyOwned(ctx, tx, id, userID); err != nil {
			return err
		}
		if hash != nil {
			if err := access.CheckTarget(ctx, tx, id, userID, "user.password"); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET email=COALESCE(LOWER($2::text),email),full_name=COALESCE($3,full_name),password_hash=COALESCE($4,password_hash),updated_at=GREATEST(updated_at+INTERVAL '1 microsecond',clock_timestamp()) WHERE id=$1`, userID, req.Email, req.FullName, hash); err != nil {
			return err
		}
		if hash != nil {
			if err := revoke(ctx, tx, id.TenantID, userID); err != nil {
				return err
			}
		}
		u, err = get(ctx, tx, id, userID, false)
		if err != nil {
			return err
		}
		return access.Audit(ctx, tx, id, "user.update", "user", userID)
	})
	return u, err
}
func (r *PostgresRepository) SoftDelete(ctx context.Context, id auth.Identity, userID string, req VersionRequest) error {
	return access.Scoped(ctx, r.pool, id, true, false, func(tx pgx.Tx) error {
		u, err := get(ctx, tx, id, userID, true)
		if err != nil {
			return err
		}
		if !u.UpdatedAt.Equal(req.ExpectedUpdatedAt) {
			return access.ErrConflict
		}
		if err := exclusivelyOwned(ctx, tx, id, userID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET deleted_at=clock_timestamp(),updated_at=GREATEST(updated_at+INTERVAL '1 microsecond',clock_timestamp()) WHERE id=$1`, userID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE tenant_users SET status='suspended',removed_at=clock_timestamp(),updated_at=GREATEST(updated_at+INTERVAL '1 microsecond',clock_timestamp()) WHERE tenant_id=$1 AND user_id=$2`, id.TenantID, userID); err != nil {
			return err
		}
		if err := revoke(ctx, tx, id.TenantID, userID); err != nil {
			return err
		}
		if err := access.Audit(ctx, tx, id, "membership.remove", "user", userID); err != nil {
			return err
		}
		return access.Audit(ctx, tx, id, "user.delete", "user", userID)
	})
}

func (r *PostgresRepository) AddMembership(ctx context.Context, id auth.Identity, req MembershipRequest) (Membership, error) {
	var m Membership
	err := access.Scoped(ctx, r.pool, id, true, false, func(tx pgx.Tx) error {
		// Establish membership via the FK before looking up the global identity.
		// No non-member profile is disclosed, and deleted targets roll back.
		tag, err := tx.Exec(ctx, `INSERT INTO tenant_users(tenant_id,user_id) VALUES($1,$2) ON CONFLICT(tenant_id,user_id) DO NOTHING`, id.TenantID, req.UserID)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23503" {
				return access.ErrNotFound
			}
			return err
		}
		u, err := scanUser(tx.QueryRow(ctx, `SELECT `+userColumns+` FROM users u JOIN tenant_users tu ON tu.user_id=u.id WHERE tu.tenant_id=$1 AND u.id=$2 AND u.deleted_at IS NULL FOR NO KEY UPDATE OF u`, id.TenantID, req.UserID))
		if err != nil {
			return err
		}
		// Re-adding a removed membership creates a fresh lifecycle and never
		// reactivates historical tokens or existing role assignments.
		var removed bool
		if err := tx.QueryRow(ctx, `SELECT removed_at IS NOT NULL FROM tenant_users WHERE tenant_id=$1 AND user_id=$2`, id.TenantID, req.UserID).Scan(&removed); err != nil {
			return err
		}
		if !removed {
			if tag.RowsAffected() == 0 {
				return access.ErrConflict
			}
		} else {
			// Role grants are retained for history; fail closed rather than restore
			// a membership with old assignments that RBAC would reactivate.
			var grants bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_roles WHERE tenant_id=$1 AND user_id=$2)`, id.TenantID, req.UserID).Scan(&grants); err != nil {
				return err
			}
			if grants {
				return access.ErrConflict
			}
			if _, err := tx.Exec(ctx, `UPDATE tenant_users SET status='active',removed_at=NULL,joined_at=clock_timestamp(),updated_at=GREATEST(updated_at+INTERVAL '1 microsecond',clock_timestamp()) WHERE tenant_id=$1 AND user_id=$2`, id.TenantID, req.UserID); err != nil {
				return err
			}
			u, err = get(ctx, tx, id, req.UserID, false)
			if err != nil {
				return err
			}
		}
		m = u.Membership
		return access.Audit(ctx, tx, id, "membership.create", "user", req.UserID)
	})
	return m, err
}
func (r *PostgresRepository) SetMembershipStatus(ctx context.Context, id auth.Identity, userID string, req MembershipStatusRequest) (Membership, error) {
	var m Membership
	err := access.Scoped(ctx, r.pool, id, true, false, func(tx pgx.Tx) error {
		u, err := get(ctx, tx, id, userID, true)
		if err != nil {
			return err
		}
		if !u.Membership.UpdatedAt.Equal(req.ExpectedUpdatedAt) {
			return access.ErrConflict
		}
		if req.Status == "active" {
			if err := access.CheckTarget(ctx, tx, id, userID, "membership.activate"); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE tenant_users SET status=$3,updated_at=GREATEST(updated_at+INTERVAL '1 microsecond',clock_timestamp()) WHERE tenant_id=$1 AND user_id=$2 AND removed_at IS NULL`, id.TenantID, userID, req.Status); err != nil {
			return err
		}
		if req.Status == "suspended" {
			if err := revoke(ctx, tx, id.TenantID, userID); err != nil {
				return err
			}
		}
		u, err = get(ctx, tx, id, userID, false)
		if err != nil {
			return err
		}
		m = u.Membership
		return access.Audit(ctx, tx, id, "membership.status", "user", userID)
	})
	return m, err
}
func (r *PostgresRepository) RemoveMembership(ctx context.Context, id auth.Identity, userID string, req VersionRequest) error {
	return access.Scoped(ctx, r.pool, id, true, false, func(tx pgx.Tx) error {
		u, err := get(ctx, tx, id, userID, true)
		if err != nil {
			return err
		}
		if !u.Membership.UpdatedAt.Equal(req.ExpectedUpdatedAt) {
			return access.ErrConflict
		}
		if _, err := tx.Exec(ctx, `UPDATE tenant_users SET status='suspended',removed_at=clock_timestamp(),updated_at=GREATEST(updated_at+INTERVAL '1 microsecond',clock_timestamp()) WHERE tenant_id=$1 AND user_id=$2`, id.TenantID, userID); err != nil {
			return err
		}
		if err := revoke(ctx, tx, id.TenantID, userID); err != nil {
			return err
		}
		return access.Audit(ctx, tx, id, "membership.remove", "user", userID)
	})
}
