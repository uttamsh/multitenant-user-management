package tenant

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/uttam/multitenant-user-management/internal/access"
	"github.com/uttam/multitenant-user-management/internal/auth"
)

type PostgresRepository struct{ pool *pgxpool.Pool }

func NewRepository(pool *pgxpool.Pool) *PostgresRepository { return &PostgresRepository{pool: pool} }

const columns = `id::text,name,code,status,created_at,updated_at`

func scan(row pgx.Row) (Tenant, error) {
	var t Tenant
	err := row.Scan(&t.ID, &t.Name, &t.Code, &t.Status, &t.CreatedAt, &t.UpdatedAt)
	return t, access.DBError(err)
}

func (r *PostgresRepository) Provision(ctx context.Context, req CreateRequest) (Tenant, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Tenant{}, err
	}
	defer access.Rollback(tx)
	t, err := scan(tx.QueryRow(ctx, `INSERT INTO tenants(name,code) VALUES($1,$2) RETURNING `+columns, req.Name, req.Code))
	if err != nil {
		return Tenant{}, err
	}
	// CLI provisioning has no authenticated actor. No request data is audited.
	if _, err := tx.Exec(ctx, `INSERT INTO audit_logs(tenant_id,action,target_type,target_id,metadata) VALUES($1,'tenant.create','tenant',$1,'{"source":"administrative_cli"}')`, t.ID); err != nil {
		return Tenant{}, err
	}
	return t, access.DBError(tx.Commit(ctx))
}
func (r *PostgresRepository) Get(ctx context.Context, id auth.Identity) (Tenant, error) {
	var t Tenant
	err := access.Scoped(ctx, r.pool, id, false, false, func(tx pgx.Tx) error {
		var err error
		t, err = scan(tx.QueryRow(ctx, `SELECT `+columns+` FROM tenants WHERE id=$1`, id.TenantID))
		return err
	})
	return t, err
}
func (r *PostgresRepository) Update(ctx context.Context, id auth.Identity, req UpdateRequest) (Tenant, error) {
	var t Tenant
	err := access.Scoped(ctx, r.pool, id, true, false, func(tx pgx.Tx) error {
		var err error
		t, err = scan(tx.QueryRow(ctx, `UPDATE tenants SET name=$2,updated_at=GREATEST(updated_at+INTERVAL '1 microsecond',clock_timestamp()) WHERE id=$1 AND updated_at=$3 RETURNING `+columns, id.TenantID, req.Name, req.ExpectedUpdatedAt))
		if err == access.ErrNotFound {
			return access.ErrConflict
		}
		if err != nil {
			return err
		}
		return access.Audit(ctx, tx, id, "tenant.update", "tenant", id.TenantID)
	})
	return t, err
}
func (r *PostgresRepository) SetStatus(ctx context.Context, id auth.Identity, req StatusRequest) (Tenant, error) {
	var t Tenant
	err := access.Scoped(ctx, r.pool, id, true, true, func(tx pgx.Tx) error {
		var err error
		t, err = scan(tx.QueryRow(ctx, `UPDATE tenants SET status=$2,updated_at=GREATEST(updated_at+INTERVAL '1 microsecond',clock_timestamp()) WHERE id=$1 AND updated_at=$3 RETURNING `+columns, id.TenantID, req.Status, req.ExpectedUpdatedAt))
		if err == access.ErrNotFound {
			return access.ErrConflict
		}
		if err != nil {
			return err
		}
		if req.Status == "suspended" {
			if _, err := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND revoked_at IS NULL`, id.TenantID); err != nil {
				return err
			}
		}
		return access.Audit(ctx, tx, id, "tenant.status", "tenant", id.TenantID)
	})
	return t, err
}
