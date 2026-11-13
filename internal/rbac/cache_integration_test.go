package rbac_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/uttam/multitenant-user-management/internal/auth"
	"github.com/uttam/multitenant-user-management/internal/rbac"
	"github.com/uttam/multitenant-user-management/internal/server"
	"github.com/uttam/multitenant-user-management/internal/user"
)

// Uses the existing isolated-schema harness, never public application tables.
func TestPostgresPermissionCache(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pool := database(t, ctx)
	revision := func(t *testing.T, tenantID string) int64 {
		t.Helper()
		var v int64
		if err := pool.QueryRow(ctx, `SELECT authorization_revision FROM tenants WHERE id=$1`, tenantID).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	fixture := func(t *testing.T, code string) (auth.Identity, string) {
		t.Helper()
		var id auth.Identity
		if err := pool.QueryRow(ctx, `INSERT INTO tenants(name,code) VALUES($1,$1) RETURNING id::text`, code).Scan(&id.TenantID); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `INSERT INTO users(email,full_name,password_hash) VALUES($1,'Token-only fixture','not-a-login-hash') RETURNING id::text`, code+"@example.test").Scan(&id.UserID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO tenant_users(tenant_id,user_id) VALUES($1,$2)`, id.TenantID, id.UserID); err != nil {
			t.Fatal(err)
		}
		before := revision(t, id.TenantID)
		result, err := rbac.Bootstrap(ctx, pool, rbac.BootstrapRequest{Approved: true, ExistingTenant: true, Code: code, AdminUserID: id.UserID})
		if err != nil {
			t.Fatal(err)
		}
		if revision(t, id.TenantID) <= before {
			t.Fatal("bootstrap did not advance authorization revision")
		}
		return id, result.RoleID
	}
	must := func(t *testing.T, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	admin, adminRole := fixture(t, "cache-alpha")
	other, _ := fixture(t, "cache-beta")
	p1, p2 := rbac.NewPolicy(pool), rbac.NewPolicy(pool)
	rs := rbac.NewService(rbac.NewRepository(pool), rbac.NewPolicy(pool))
	us := user.NewService(user.NewRepository(pool), rbac.NewPolicy(pool))

	t.Run("same JWT negative grant revoke and two independent caches", func(t *testing.T) {
		member, err := us.Create(ctx, admin, user.CreateRequest{Email: "cache-member@example.test", FullName: "Cache Member", Password: "integration-only-password"})
		must(t, err)
		// Identical user UUID in another tenant must not inherit the first tenant's rights.
		_, err = us.AddMembership(ctx, other, user.MembershipRequest{UserID: member.ID})
		must(t, err)
		identity := auth.Identity{TenantID: admin.TenantID, UserID: member.ID}
		secondIdentity := auth.Identity{TenantID: other.TenantID, UserID: member.ID}
		tokens, err := auth.NewTokens(strings.Repeat("cache-test-key", 4), "cache-integration", time.Minute, time.Hour)
		must(t, err)
		pair, _, err := tokens.Issue(identity)
		must(t, err)
		logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
		checkHTTP := func(want int) {
			t.Helper()
			for _, policy := range []*rbac.Policy{p1, p2} {
				router := server.NewRouter(pool, time.Second, logger, user.NewHandler(user.NewService(user.NewRepository(pool), policy), tokens, time.Second))
				for i := 0; i < 2; i++ {
					request := httptest.NewRequest("GET", "/api/v1/users", nil)
					request.Header.Set("Authorization", "Bearer "+pair.AccessToken)
					response := httptest.NewRecorder()
					router.ServeHTTP(response, request)
					if response.Code != want {
						t.Fatalf("same JWT HTTP %d, want %d", response.Code, want)
					}
				}
			}
		}
		checkHTTP(403)
		role, err := rs.CreateRole(ctx, admin, rbac.CreateRoleRequest{Name: "cache-reader"})
		must(t, err)
		permission := rbac.PermissionRequest{Resource: "user", Action: "read"}
		must(t, rs.ChangePermission(ctx, admin, role.ID, permission, true))
		must(t, rs.ChangeUserRole(ctx, admin, member.ID, role.ID, true))
		checkHTTP(200)
		if err := p1.Check(ctx, secondIdentity, "user.read"); !errors.Is(err, auth.ErrForbidden) {
			t.Fatal("same user UUID leaked permissions across tenants", err)
		}
		before := revision(t, admin.TenantID)
		must(t, rs.ChangePermission(ctx, admin, role.ID, permission, false))
		if revision(t, admin.TenantID) <= before {
			t.Fatal("permission revocation did not advance revision")
		}
		checkHTTP(403)
		must(t, rs.ChangePermission(ctx, admin, role.ID, permission, true))
		checkHTTP(200)
		must(t, rs.ChangeUserRole(ctx, admin, member.ID, role.ID, false))
		checkHTTP(403)
		must(t, rs.ChangeUserRole(ctx, admin, member.ID, role.ID, true))
		checkHTTP(200)
		must(t, rs.DeleteRole(ctx, admin, role.ID, rbac.DeleteRoleRequest{ExpectedVersion: role.Version}))
		checkHTTP(403)
	})

	t.Run("rollback and invisible uncommitted grants", func(t *testing.T) {
		before := revision(t, admin.TenantID)
		tx, err := pool.Begin(ctx)
		must(t, err)
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2`, admin.TenantID, adminRole)
		must(t, err)
		var inside int64
		must(t, tx.QueryRow(ctx, `SELECT authorization_revision FROM tenants WHERE id=$1`, admin.TenantID).Scan(&inside))
		if inside <= before {
			t.Fatal("revision missing inside mutation transaction")
		}
		// Another connection sees both old grants and the old revision, never half a change.
		must(t, rbac.NewPolicy(pool).Check(ctx, admin, "user.read"))
		must(t, tx.Rollback(ctx))
		if revision(t, admin.TenantID) != before {
			t.Fatal("rollback advanced authoritative revision")
		}
		_, err = pool.Exec(ctx, `CREATE FUNCTION cache_reject_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='role.create' THEN RAISE EXCEPTION 'test audit rejection'; END IF; RETURN NEW; END $$;
 CREATE TRIGGER cache_reject_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION cache_reject_audit()`)
		must(t, err)
		_, err = rs.CreateRole(ctx, admin, rbac.CreateRoleRequest{Name: "must-rollback"})
		if err == nil {
			t.Fatal("audit failure committed mutation")
		}
		if revision(t, admin.TenantID) != before {
			t.Fatal("audit failure committed revision")
		}
		_, err = pool.Exec(ctx, `DROP TRIGGER cache_reject_audit ON audit_logs; DROP FUNCTION cache_reject_audit()`)
		must(t, err)
	})

	t.Run("concurrent PostgreSQL cache population", func(t *testing.T) {
		policy := rbac.NewPolicy(pool)
		var wg sync.WaitGroup
		for i := 0; i < 32; i++ {
			wg.Go(func() {
				if err := policy.Check(ctx, admin, "user.read"); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
	})

	t.Run("new tenant bootstrap and role profile revision", func(t *testing.T) {
		result, err := rbac.Bootstrap(ctx, pool, rbac.BootstrapRequest{Approved: true, Name: "Cache New", Code: "cache-new", AdminUserID: admin.UserID})
		must(t, err)
		if revision(t, result.TenantID) == 0 {
			t.Fatal("new-tenant bootstrap left revision at zero")
		}
		before := revision(t, admin.TenantID)
		role, err := rs.GetRole(ctx, admin, adminRole)
		must(t, err)
		_, err = rs.UpdateRole(ctx, admin, adminRole, rbac.UpdateRoleRequest{Name: "renamed-cache-admin", ExpectedVersion: role.Version})
		must(t, err)
		if revision(t, admin.TenantID) <= before {
			t.Fatal("role update did not advance revision")
		}
	})

	t.Run("permission identifier changes invalidate every linked tenant", func(t *testing.T) {
		must(t, p1.Check(ctx, admin, "user.read"))
		must(t, p2.Check(ctx, other, "user.read"))
		beforeA, beforeB := revision(t, admin.TenantID), revision(t, other.TenantID)
		_, err := pool.Exec(ctx, `UPDATE permissions SET action='cache-test-unsupported' WHERE resource='user' AND action='read'`)
		must(t, err)
		if revision(t, admin.TenantID) <= beforeA || revision(t, other.TenantID) <= beforeB {
			t.Fatal("global permission edit missed a linked tenant")
		}
		for _, tc := range []struct {
			policy *rbac.Policy
			id     auth.Identity
		}{{p1, admin}, {p2, other}} {
			if err := tc.policy.Check(ctx, tc.id, "user.read"); !errors.Is(err, auth.ErrForbidden) {
				t.Fatal("global permission edit left cached allow", err)
			}
		}
		_, err = pool.Exec(ctx, `UPDATE permissions SET action='read' WHERE resource='user' AND action='cache-test-unsupported'`)
		must(t, err)
		must(t, p1.Check(ctx, admin, "user.read"))
		must(t, p2.Check(ctx, other, "user.read"))
	})

	for _, scenario := range []struct{ name, sql string }{
		{"suspended-tenant", `UPDATE tenants SET status='suspended' WHERE id=$1`},
		{"suspended-membership", `UPDATE tenant_users SET status='suspended' WHERE tenant_id=$1 AND user_id=$2`},
		{"removed-membership", `UPDATE tenant_users SET status='suspended',removed_at=clock_timestamp() WHERE tenant_id=$1 AND user_id=$2`},
		{"deleted-user", `UPDATE users SET deleted_at=clock_timestamp() WHERE id=$2 AND EXISTS(SELECT 1 FROM tenant_users WHERE tenant_id=$1 AND user_id=$2)`},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			id, _ := fixture(t, "cache-"+scenario.name)
			policy := rbac.NewPolicy(pool)
			must(t, policy.Check(ctx, id, "user.read"))
			before := revision(t, id.TenantID)
			var err error
			if scenario.name == "suspended-tenant" {
				_, err = pool.Exec(ctx, scenario.sql, id.TenantID)
			} else {
				_, err = pool.Exec(ctx, scenario.sql, id.TenantID, id.UserID)
			}
			must(t, err)
			if revision(t, id.TenantID) <= before {
				t.Fatal("identity state change did not advance revision")
			}
			if err := policy.Check(ctx, id, "user.read"); !errors.Is(err, auth.ErrForbidden) {
				t.Fatal("inactive identity used cached allow", err)
			}
		})
	}

	t.Run("database failure with warm cache", func(t *testing.T) {
		separate, err := pgxpool.NewWithConfig(ctx, pool.Config())
		must(t, err)
		defer separate.Close()
		policy := rbac.NewPolicy(separate)
		must(t, policy.Check(ctx, admin, "user.read"))
		separate.Close()
		if err := policy.Check(ctx, admin, "user.read"); err == nil {
			t.Fatal("closed database authorized a warm cached permission")
		}
	})
}
