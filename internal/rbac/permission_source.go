package rbac

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/uttam/multitenant-user-management/internal/auth"
)

type permissionSource interface {
	revision(context.Context, auth.Identity) (int64, error)
	snapshot(context.Context, auth.Identity) (int64, permissionSet, error)
}

type postgresPermissions struct{ db queryer }

func identityError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.ErrForbidden
	}
	return err
}

func (p postgresPermissions) revision(ctx context.Context, id auth.Identity) (int64, error) {
	var revision int64
	err := p.db.QueryRow(ctx, `SELECT t.authorization_revision`+activeIdentity, id.TenantID, id.UserID).Scan(&revision)
	return revision, identityError(err)
}

func (p postgresPermissions) snapshot(ctx context.Context, id auth.Identity) (int64, permissionSet, error) {
	var revision int64
	var actions []string
	// One PostgreSQL statement snapshot contains both the authoritative revision
	// and grants. A concurrent commit is either visible in both, or in neither.
	// Do not label these grants with the revision from the earlier probe.
	err := p.db.QueryRow(ctx, `SELECT t.authorization_revision, ARRAY(
 SELECT DISTINCT p.resource || '.' || p.action FROM user_roles ur
 JOIN roles r ON r.tenant_id=ur.tenant_id AND r.id=ur.role_id
 JOIN role_permissions rp ON rp.tenant_id=r.tenant_id AND rp.role_id=r.id
 JOIN permissions p ON p.id=rp.permission_id
 WHERE ur.tenant_id=$1 AND ur.user_id=$2)`+activeIdentity, id.TenantID, id.UserID).Scan(&revision, &actions)
	if err != nil {
		return 0, 0, identityError(err)
	}
	return revision, permissionsFromActions(actions), nil
}
