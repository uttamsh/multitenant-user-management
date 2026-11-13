package database

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

type schemaReader interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// RequireAuthorizationSchema is a read-only startup guard, not a migration
// runner. Resolve tables through the same search_path as application queries.
func RequireAuthorizationSchema(ctx context.Context, db schemaReader, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var ready bool
	err := db.QueryRow(ctx, `WITH expected(relation, name) AS (VALUES
 ('roles','roles_authorization_revision'),
 ('role_permissions','role_permissions_authorization_revision'),
 ('user_roles','user_roles_authorization_revision'),
 ('tenant_users','tenant_users_authorization_revision'),
 ('tenants','tenants_status_authorization_revision'),
 ('users','users_state_authorization_revision'),
 ('permissions','permissions_identity_authorization_revision'))
 SELECT EXISTS(SELECT 1 FROM pg_attribute
 WHERE attrelid=to_regclass('tenants') AND attname='authorization_revision'
 AND atttypid='int8'::regtype AND attnotnull AND NOT attisdropped)
 AND NOT EXISTS(SELECT 1 FROM expected e WHERE NOT EXISTS(
 SELECT 1 FROM pg_trigger t WHERE t.tgrelid=to_regclass(e.relation)
 AND t.tgname=e.name AND t.tgenabled IN ('O','A') AND NOT t.tgisinternal))`).Scan(&ready)
	if err != nil {
		return errors.New("could not verify authorization schema; check database access and apply migrations 001-003 explicitly")
	}
	if !ready {
		return errors.New("authorization schema is not ready: migration 003 and all seven enabled revision triggers are required; apply migrations explicitly before starting the API")
	}
	return nil
}
