package rbac

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/uttam/multitenant-user-management/internal/access"
	"github.com/uttam/multitenant-user-management/internal/tenant"
)

type BootstrapRequest struct {
	Approved       bool
	ExistingTenant bool
	Name           string
	Code           string
	AdminUserID    string
}
type BootstrapResult struct{ TenantID, RoleID, AdminUserID string }

// Bootstrap is an operator-only transaction, reachable through the provisioning
// CLI with both --administrative and --bootstrap-admin. No HTTP route calls it.
// It initializes only tenants without roles or assignments, never repairs grants.
func Bootstrap(ctx context.Context, pool *pgxpool.Pool, req BootstrapRequest) (BootstrapResult, error) {
	if !req.Approved {
		return BootstrapResult{}, access.ErrInvalid
	}
	if !access.UUID(req.AdminUserID) {
		return BootstrapResult{}, access.ErrInvalid
	}
	req.Code = strings.TrimSpace(req.Code)
	if req.Code == "" || !utf8.ValidString(req.Code) || utf8.RuneCountInString(req.Code) > 50 || strings.ContainsRune(req.Code, '\x00') {
		return BootstrapResult{}, access.ErrInvalid
	}
	if !req.ExistingTenant {
		v, err := tenant.NormalizeCreate(tenant.CreateRequest{Name: req.Name, Code: req.Code})
		if err != nil {
			return BootstrapResult{}, err
		}
		req.Name, req.Code = v.Name, v.Code
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return BootstrapResult{}, err
	}
	defer access.Rollback(tx)
	result := BootstrapResult{AdminUserID: req.AdminUserID}
	if req.ExistingTenant {
		if err := tx.QueryRow(ctx, `SELECT id::text FROM tenants WHERE code=$1 AND status='active' FOR UPDATE`, req.Code).Scan(&result.TenantID); err != nil {
			return BootstrapResult{}, access.DBError(err)
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users u JOIN tenant_users tu ON tu.user_id=u.id WHERE tu.tenant_id=$1 AND u.id=$2 AND u.deleted_at IS NULL AND tu.status='active' AND tu.removed_at IS NULL)`, result.TenantID, req.AdminUserID).Scan(&exists); err != nil {
			return BootstrapResult{}, err
		}
		if !exists {
			return BootstrapResult{}, access.ErrNotFound
		}
	} else {
		if err := tx.QueryRow(ctx, `INSERT INTO tenants(name,code) VALUES($1,$2) RETURNING id::text`, req.Name, req.Code).Scan(&result.TenantID); err != nil {
			return BootstrapResult{}, access.DBError(err)
		}
		var userID string
		if err := tx.QueryRow(ctx, `SELECT id::text FROM users WHERE id=$1 AND deleted_at IS NULL FOR SHARE`, req.AdminUserID).Scan(&userID); err != nil {
			return BootstrapResult{}, access.DBError(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO tenant_users(tenant_id,user_id) VALUES($1,$2)`, result.TenantID, req.AdminUserID); err != nil {
			return BootstrapResult{}, err
		}
	}
	var initialized bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM roles WHERE tenant_id=$1) OR EXISTS(SELECT 1 FROM user_roles WHERE tenant_id=$1) OR EXISTS(SELECT 1 FROM audit_logs WHERE tenant_id=$1 AND action='tenant.admin_bootstrap')`, result.TenantID).Scan(&initialized); err != nil {
		return BootstrapResult{}, err
	}
	if initialized {
		return BootstrapResult{}, access.ErrConflict
	}
	// CLI audit actor is NULL: the selected administrator is not the operator.
	audit := func(action, targetType, targetID, relatedID string) error {
		_, err := tx.Exec(ctx, `INSERT INTO audit_logs(tenant_id,action,target_type,target_id,metadata) VALUES($1,$2,$3,$4,jsonb_build_object('source','administrative_cli','related_id',$5::text))`, result.TenantID, action, targetType, targetID, relatedID)
		return err
	}
	if !req.ExistingTenant {
		if err := audit("tenant.create", "tenant", result.TenantID, ""); err != nil {
			return BootstrapResult{}, err
		}
		if err := audit("membership.create", "user", req.AdminUserID, ""); err != nil {
			return BootstrapResult{}, err
		}
	}
	if err := tx.QueryRow(ctx, `INSERT INTO roles(tenant_id,name,description) VALUES($1,'tenant-admin','Initial tenant administrator') RETURNING id::text`, result.TenantID).Scan(&result.RoleID); err != nil {
		return BootstrapResult{}, access.DBError(err)
	}
	if err := audit("role.create", "role", result.RoleID, ""); err != nil {
		return BootstrapResult{}, err
	}
	for _, p := range Catalog() {
		permissionID, created, err := ensurePermission(ctx, tx, PermissionRequest{Resource: p.Resource, Action: p.Action})
		if err != nil {
			return BootstrapResult{}, err
		}
		if created {
			if err := audit("permission.create", "permission", permissionID, ""); err != nil {
				return BootstrapResult{}, err
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO role_permissions(tenant_id,role_id,permission_id) VALUES($1,$2,$3)`, result.TenantID, result.RoleID, permissionID); err != nil {
			return BootstrapResult{}, err
		}
		if err := audit("role_permission.assign", "role", result.RoleID, permissionID); err != nil {
			return BootstrapResult{}, err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO user_roles(tenant_id,user_id,role_id) VALUES($1,$2,$3)`, result.TenantID, req.AdminUserID, result.RoleID); err != nil {
		return BootstrapResult{}, err
	}
	if err := audit("user_role.assign", "user", req.AdminUserID, result.RoleID); err != nil {
		return BootstrapResult{}, err
	}
	if err := audit("tenant.admin_bootstrap", "user", req.AdminUserID, result.RoleID); err != nil {
		return BootstrapResult{}, err
	}
	return result, access.DBError(tx.Commit(ctx))
}
