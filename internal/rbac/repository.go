package rbac

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/uttam/multitenant-user-management/internal/access"
	"github.com/uttam/multitenant-user-management/internal/auth"
)

type Repository interface {
	CreateRole(context.Context, auth.Identity, CreateRoleRequest) (Role, error)
	ListRoles(context.Context, auth.Identity, int, int) (RolePage, error)
	GetRole(context.Context, auth.Identity, string) (Role, error)
	UpdateRole(context.Context, auth.Identity, string, UpdateRoleRequest) (Role, error)
	DeleteRole(context.Context, auth.Identity, string, DeleteRoleRequest) error
	Catalog(context.Context, auth.Identity) ([]Permission, error)
	RolePermissions(context.Context, auth.Identity, string) ([]Permission, error)
	ChangePermission(context.Context, auth.Identity, string, PermissionRequest, bool) error
	UserRoles(context.Context, auth.Identity, string) ([]Role, error)
	ChangeUserRole(context.Context, auth.Identity, string, string, bool) error
	Effective(context.Context, auth.Identity, string) ([]Permission, error)
}
type PostgresRepository struct{ pool *pgxpool.Pool }

func NewRepository(pool *pgxpool.Pool) *PostgresRepository { return &PostgresRepository{pool} }

const roleColumns = `id::text,name,COALESCE(description,''),created_at`

func scanRole(row pgx.Row) (Role, error) {
	var r Role
	err := row.Scan(&r.ID, &r.Name, &r.Description, &r.CreatedAt)
	r.setVersion()
	return r, access.DBError(err)
}
func findRole(ctx context.Context, tx pgx.Tx, id auth.Identity, roleID string) (Role, error) {
	return scanRole(tx.QueryRow(ctx, `SELECT `+roleColumns+` FROM roles WHERE tenant_id=$1 AND id=$2`, id.TenantID, roleID))
}
func findUser(ctx context.Context, tx pgx.Tx, id auth.Identity, userID string) error {
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenant_users tu JOIN users u ON u.id=tu.user_id WHERE tu.tenant_id=$1 AND tu.user_id=$2 AND tu.removed_at IS NULL AND u.deleted_at IS NULL)`, id.TenantID, userID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return access.ErrNotFound
	}
	return nil
}
func grantAudit(ctx context.Context, tx pgx.Tx, id auth.Identity, action, targetType, targetID, relatedID string) error {
	_, err := tx.Exec(ctx, `INSERT INTO audit_logs(tenant_id,actor_id,action,target_type,target_id,metadata) VALUES($1,$2,$3,$4,$5,jsonb_build_object('related_id',$6::text))`, id.TenantID, id.UserID, action, targetType, targetID, relatedID)
	return err
}
func (r *PostgresRepository) CreateRole(ctx context.Context, id auth.Identity, req CreateRoleRequest) (Role, error) {
	var role Role
	err := access.Scoped(ctx, r.pool, id, true, false, func(tx pgx.Tx) error {
		var err error
		role, err = scanRole(tx.QueryRow(ctx, `INSERT INTO roles(tenant_id,name,description) VALUES($1,$2,$3) RETURNING `+roleColumns, id.TenantID, req.Name, req.Description))
		if err != nil {
			return err
		}
		return access.Audit(ctx, tx, id, "role.create", "role", role.ID)
	})
	return role, err
}
func (r *PostgresRepository) ListRoles(ctx context.Context, id auth.Identity, page, size int) (RolePage, error) {
	result := RolePage{Items: []Role{}, Page: page, PageSize: size}
	err := access.Scoped(ctx, r.pool, id, false, false, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM roles WHERE tenant_id=$1`, id.TenantID).Scan(&result.Total); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+roleColumns+` FROM roles WHERE tenant_id=$1 ORDER BY created_at,id LIMIT $2 OFFSET $3`, id.TenantID, size, (page-1)*size)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			role, err := scanRole(rows)
			if err != nil {
				return err
			}
			result.Items = append(result.Items, role)
		}
		return rows.Err()
	})
	return result, err
}
func (r *PostgresRepository) GetRole(ctx context.Context, id auth.Identity, roleID string) (Role, error) {
	var role Role
	err := access.Scoped(ctx, r.pool, id, false, false, func(tx pgx.Tx) error { var err error; role, err = findRole(ctx, tx, id, roleID); return err })
	return role, err
}
func (r *PostgresRepository) UpdateRole(ctx context.Context, id auth.Identity, roleID string, req UpdateRoleRequest) (Role, error) {
	var role Role
	err := access.Scoped(ctx, r.pool, id, true, false, func(tx pgx.Tx) error {
		old, err := findRole(ctx, tx, id, roleID)
		if err != nil {
			return err
		}
		if old.Version != req.ExpectedVersion {
			return access.ErrConflict
		}
		role, err = scanRole(tx.QueryRow(ctx, `UPDATE roles SET name=$3,description=$4 WHERE tenant_id=$1 AND id=$2 RETURNING `+roleColumns, id.TenantID, roleID, req.Name, req.Description))
		if err != nil {
			return err
		}
		return access.Audit(ctx, tx, id, "role.update", "role", roleID)
	})
	return role, err
}
func (r *PostgresRepository) DeleteRole(ctx context.Context, id auth.Identity, roleID string, req DeleteRoleRequest) error {
	return access.Scoped(ctx, r.pool, id, true, false, func(tx pgx.Tx) error {
		role, err := findRole(ctx, tx, id, roleID)
		if err != nil {
			return err
		}
		if role.Version != req.ExpectedVersion {
			return access.ErrConflict
		}
		// Audit each removed relationship before deleting only this tenant's rows.
		if _, err := tx.Exec(ctx, `INSERT INTO audit_logs(tenant_id,actor_id,action,target_type,target_id,metadata)
 SELECT tenant_id,$3,'user_role.remove','user',user_id,jsonb_build_object('related_id',role_id::text) FROM user_roles WHERE tenant_id=$1 AND role_id=$2`, id.TenantID, roleID, id.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO audit_logs(tenant_id,actor_id,action,target_type,target_id,metadata)
 SELECT tenant_id,$3,'role_permission.remove','role',role_id,jsonb_build_object('related_id',permission_id::text) FROM role_permissions WHERE tenant_id=$1 AND role_id=$2`, id.TenantID, roleID, id.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM user_roles WHERE tenant_id=$1 AND role_id=$2`, id.TenantID, roleID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2`, id.TenantID, roleID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM roles WHERE tenant_id=$1 AND id=$2`, id.TenantID, roleID); err != nil {
			return err
		}
		return access.Audit(ctx, tx, id, "role.delete", "role", roleID)
	})
}
func scanPermissions(rows pgx.Rows) ([]Permission, error) {
	defer rows.Close()
	result := []Permission{}
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.ID, &p.Resource, &p.Action); err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, rows.Err()
}
func (r *PostgresRepository) Catalog(ctx context.Context, id auth.Identity) ([]Permission, error) {
	var result []Permission
	err := access.Scoped(ctx, r.pool, id, false, false, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text,resource,action FROM permissions ORDER BY resource,action`)
		if err != nil {
			return err
		}
		result, err = scanPermissions(rows)
		return err
	})
	return result, err
}
func rolePermissions(ctx context.Context, tx pgx.Tx, id auth.Identity, roleID string) ([]Permission, error) {
	rows, err := tx.Query(ctx, `SELECT p.id::text,p.resource,p.action FROM permissions p JOIN role_permissions rp ON rp.permission_id=p.id WHERE rp.tenant_id=$1 AND rp.role_id=$2 ORDER BY p.resource,p.action`, id.TenantID, roleID)
	if err != nil {
		return nil, err
	}
	return scanPermissions(rows)
}
func (r *PostgresRepository) RolePermissions(ctx context.Context, id auth.Identity, roleID string) ([]Permission, error) {
	var result []Permission
	err := access.Scoped(ctx, r.pool, id, false, false, func(tx pgx.Tx) error {
		if _, err := findRole(ctx, tx, id, roleID); err != nil {
			return err
		}
		var err error
		result, err = rolePermissions(ctx, tx, id, roleID)
		return err
	})
	return result, err
}
func ensurePermission(ctx context.Context, tx pgx.Tx, p PermissionRequest) (string, bool, error) {
	tag, err := tx.Exec(ctx, `INSERT INTO permissions(resource,action) VALUES($1,$2) ON CONFLICT(resource,action) DO NOTHING`, p.Resource, p.Action)
	if err != nil {
		return "", false, err
	}
	var id string
	err = tx.QueryRow(ctx, `SELECT id::text FROM permissions WHERE resource=$1 AND action=$2`, p.Resource, p.Action).Scan(&id)
	return id, tag.RowsAffected() == 1, err
}
func (r *PostgresRepository) ChangePermission(ctx context.Context, id auth.Identity, roleID string, req PermissionRequest, assign bool) error {
	return access.Scoped(ctx, r.pool, id, true, false, func(tx pgx.Tx) error {
		if _, err := findRole(ctx, tx, id, roleID); err != nil {
			return err
		}
		if assign {
			// Delegation cannot grant a permission the actor does not currently hold.
			if err := check(ctx, tx, id, req.Resource+"."+req.Action); err != nil {
				return err
			}
			permissionID, created, err := ensurePermission(ctx, tx, req)
			if err != nil {
				return err
			}
			if created {
				if err := access.Audit(ctx, tx, id, "permission.create", "permission", permissionID); err != nil {
					return err
				}
			}
			tag, err := tx.Exec(ctx, `INSERT INTO role_permissions(tenant_id,role_id,permission_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, id.TenantID, roleID, permissionID)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				return access.ErrConflict
			}
			return grantAudit(ctx, tx, id, "role_permission.assign", "role", roleID, permissionID)
		}
		var permissionID string
		err := tx.QueryRow(ctx, `DELETE FROM role_permissions rp USING permissions p WHERE rp.permission_id=p.id AND rp.tenant_id=$1 AND rp.role_id=$2 AND p.resource=$3 AND p.action=$4 RETURNING p.id::text`, id.TenantID, roleID, req.Resource, req.Action).Scan(&permissionID)
		if err != nil {
			return err
		}
		return grantAudit(ctx, tx, id, "role_permission.remove", "role", roleID, permissionID)
	})
}
func (r *PostgresRepository) UserRoles(ctx context.Context, id auth.Identity, userID string) ([]Role, error) {
	result := []Role{}
	err := access.Scoped(ctx, r.pool, id, false, false, func(tx pgx.Tx) error {
		if err := findUser(ctx, tx, id, userID); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT r.id::text,r.name,COALESCE(r.description,''),r.created_at FROM roles r JOIN user_roles ur ON ur.tenant_id=r.tenant_id AND ur.role_id=r.id WHERE ur.tenant_id=$1 AND ur.user_id=$2 ORDER BY r.name,r.id`, id.TenantID, userID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			role, err := scanRole(rows)
			if err != nil {
				return err
			}
			result = append(result, role)
		}
		return rows.Err()
	})
	return result, err
}
func (r *PostgresRepository) ChangeUserRole(ctx context.Context, id auth.Identity, userID, roleID string, assign bool) error {
	return access.Scoped(ctx, r.pool, id, true, false, func(tx pgx.Tx) error {
		if _, err := findRole(ctx, tx, id, roleID); err != nil {
			return err
		}
		if err := findUser(ctx, tx, id, userID); err != nil {
			return err
		}
		if assign {
			permissions, err := rolePermissions(ctx, tx, id, roleID)
			if err != nil {
				return err
			}
			for _, p := range permissions {
				if err := check(ctx, tx, id, p.Resource+"."+p.Action); err != nil {
					return err
				}
			}
			tag, err := tx.Exec(ctx, `INSERT INTO user_roles(tenant_id,user_id,role_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, id.TenantID, userID, roleID)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				return access.ErrConflict
			}
			return grantAudit(ctx, tx, id, "user_role.assign", "user", userID, roleID)
		}
		tag, err := tx.Exec(ctx, `DELETE FROM user_roles WHERE tenant_id=$1 AND user_id=$2 AND role_id=$3`, id.TenantID, userID, roleID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return access.ErrNotFound
		}
		return grantAudit(ctx, tx, id, "user_role.remove", "user", userID, roleID)
	})
}
func (r *PostgresRepository) Effective(ctx context.Context, id auth.Identity, userID string) ([]Permission, error) {
	var result []Permission
	err := access.Scoped(ctx, r.pool, id, false, false, func(tx pgx.Tx) error {
		if err := findUser(ctx, tx, id, userID); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT DISTINCT p.id::text,p.resource,p.action FROM permissions p
 JOIN role_permissions rp ON rp.permission_id=p.id JOIN roles r ON r.id=rp.role_id AND r.tenant_id=rp.tenant_id
 JOIN user_roles ur ON ur.role_id=r.id AND ur.tenant_id=r.tenant_id
 JOIN tenant_users tu ON tu.user_id=ur.user_id AND tu.tenant_id=ur.tenant_id
 WHERE ur.tenant_id=$1 AND ur.user_id=$2 AND tu.status='active' AND tu.removed_at IS NULL ORDER BY p.resource,p.action`, id.TenantID, userID)
		if err != nil {
			return err
		}
		permissions, err := scanPermissions(rows)
		if err != nil {
			return err
		}
		result = []Permission{}
		for _, p := range permissions {
			if supported(p.Resource, p.Action) {
				result = append(result, p)
			}
		}
		return nil
	})
	return result, err
}
