package rbac

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/uttam/multitenant-user-management/internal/access"
	"github.com/uttam/multitenant-user-management/internal/auth"
)

type queryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}
type Policy struct{ pool *pgxpool.Pool }

func NewPolicy(pool *pgxpool.Pool) *Policy { return &Policy{pool} }
func (p *Policy) Check(ctx context.Context, id auth.Identity, action string) error {
	return check(ctx, p.pool, id, action)
}
func (p *Policy) CheckTx(ctx context.Context, tx pgx.Tx, id auth.Identity, action string) error {
	return check(ctx, tx, id, action)
}

func (p *Policy) CheckTargetTx(ctx context.Context, tx pgx.Tx, id auth.Identity, targetID, operation string) error {
	if operation != "user.password" && operation != "membership.activate" {
		return auth.ErrForbidden
	}
	// Include dormant role assignments: reactivation/password resets must not
	// transfer privileges the caller does not hold. Target scope is validated by
	// the repository before this check, and the tenant lock prevents grant races.
	rows, err := tx.Query(ctx, `SELECT DISTINCT p.id::text,p.resource,p.action FROM permissions p
 JOIN role_permissions rp ON rp.permission_id=p.id JOIN user_roles ur ON ur.role_id=rp.role_id AND ur.tenant_id=rp.tenant_id
 WHERE ur.tenant_id=$1 AND ur.user_id=$2`, id.TenantID, targetID)
	if err != nil {
		return err
	}
	permissions, err := scanPermissions(rows)
	if err != nil {
		return err
	}
	for _, permission := range permissions {
		if supported(permission.Resource, permission.Action) {
			if err := check(ctx, tx, id, permission.Resource+"."+permission.Action); err != nil {
				return err
			}
		}
	}
	return nil
}

const activeIdentity = ` FROM tenant_users tu JOIN tenants t ON t.id=tu.tenant_id JOIN users u ON u.id=tu.user_id
 WHERE tu.tenant_id=$1 AND tu.user_id=$2 AND t.status='active' AND tu.status='active' AND tu.removed_at IS NULL AND u.deleted_at IS NULL `
const permissionExists = `EXISTS(SELECT 1 FROM user_roles ur
 JOIN roles r ON r.tenant_id=ur.tenant_id AND r.id=ur.role_id
 JOIN role_permissions rp ON rp.tenant_id=r.tenant_id AND rp.role_id=r.id
 JOIN permissions p ON p.id=rp.permission_id
 WHERE ur.tenant_id=$1 AND ur.user_id=$2 AND p.resource=$3 AND p.action=$4)`

func check(ctx context.Context, q queryer, id auth.Identity, action string) error {
	if !access.UUID(id.UserID) || !access.UUID(id.TenantID) {
		return auth.ErrUnauthorized
	}
	resource, verb, ok := strings.Cut(action, ".")
	if action != "identity.active" && (!ok || !supported(resource, verb)) {
		return auth.ErrForbidden
	}
	var allowed bool
	sql := `SELECT EXISTS(SELECT 1` + activeIdentity
	args := []any{id.TenantID, id.UserID}
	if action != "identity.active" {
		sql += `AND ` + permissionExists
		args = append(args, resource, verb)
	}
	if err := q.QueryRow(ctx, sql+`)`, args...).Scan(&allowed); err != nil {
		return err
	}
	if !allowed {
		return auth.ErrForbidden
	}
	return nil
}
