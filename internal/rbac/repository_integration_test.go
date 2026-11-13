package rbac_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/uttam/multitenant-user-management/internal/access"
	"github.com/uttam/multitenant-user-management/internal/auth"
	"github.com/uttam/multitenant-user-management/internal/rbac"
	"github.com/uttam/multitenant-user-management/internal/server"
	"github.com/uttam/multitenant-user-management/internal/tenant"
	"github.com/uttam/multitenant-user-management/internal/user"
	"golang.org/x/crypto/bcrypt"
)

func database(t *testing.T, ctx context.Context) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("RBAC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set RBAC_TEST_DATABASE_URL to run isolated RBAC integration tests")
	}
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("invalid test database configuration")
	}
	var seed [12]byte
	if _, err := rand.Read(seed[:]); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	schema := "rbac_test_" + hex.EncodeToString(seed[:])
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close()
		t.Fatal("could not create isolated RBAC schema")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error("isolated RBAC schema cleanup failed")
		}
		admin.Close()
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid test database configuration")
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.MaxConns = 12
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	var current string
	if err := pool.QueryRow(ctx, "SELECT current_schema()").Scan(&current); err != nil || current != schema {
		t.Fatal("refusing to test outside isolated schema")
	}
	files, err := filepath.Glob(filepath.Join("..", "..", "migrations", "*.sql"))
	if err != nil || len(files) < 2 {
		t.Fatal("migrations missing")
	}
	for _, file := range files {
		sql, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, string(sql)); err != nil {
			t.Fatal("isolated migration failed")
		}
	}
	return pool
}

func TestPostgresRBAC(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pool := database(t, ctx)
	policy := rbac.NewPolicy(pool)
	repo := rbac.NewRepository(pool)
	rs := rbac.NewService(repo, policy)
	ts := tenant.NewService(tenant.NewRepository(pool), policy)
	us := user.NewService(user.NewRepository(pool), policy)
	assertErr := func(t *testing.T, err, want error) {
		t.Helper()
		if !errors.Is(err, want) {
			t.Fatalf("error=%v, want %v", err, want)
		}
	}
	fixture := func(code string) (auth.Identity, string) {
		t.Helper()
		v, err := ts.Provision(ctx, tenant.CreateRequest{Name: code, Code: code})
		if err != nil {
			t.Fatal(err)
		}
		hash, err := bcrypt.GenerateFromPassword([]byte("integration-password"), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		var userID string
		if err := pool.QueryRow(ctx, `INSERT INTO users(email,full_name,password_hash) VALUES($1,'Operator Selected',$2) RETURNING id::text`, code+"@example.test", string(hash)).Scan(&userID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO tenant_users(tenant_id,user_id) VALUES($1,$2)`, v.ID, userID); err != nil {
			t.Fatal(err)
		}
		result, err := rbac.Bootstrap(ctx, pool, rbac.BootstrapRequest{Approved: true, ExistingTenant: true, Code: code, AdminUserID: userID})
		if err != nil {
			t.Fatal(err)
		}
		return auth.Identity{UserID: userID, TenantID: v.ID}, result.RoleID
	}
	a, adminRole := fixture("rbac-alpha")
	b, bRole := fixture("rbac-beta")
	create := func(t *testing.T, id auth.Identity, email string) user.User {
		t.Helper()
		u, err := us.Create(ctx, id, user.CreateRequest{Email: email, FullName: "RBAC Member", Password: "integration-password"})
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	role := func(t *testing.T, name string) rbac.Role {
		t.Helper()
		r, err := rs.CreateRole(ctx, a, rbac.CreateRoleRequest{Name: name})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	grant := func(t *testing.T, roleID, resource, action string) {
		t.Helper()
		if err := rs.ChangePermission(ctx, a, roleID, rbac.PermissionRequest{Resource: resource, Action: action}, true); err != nil {
			t.Fatal(err)
		}
	}
	member := create(t, a, "rbac-member@example.test")
	memberID := auth.Identity{UserID: member.ID, TenantID: a.TenantID}
	t.Run("bootstrap grants explicit administrator only", func(t *testing.T) {
		permissions, err := rs.Effective(ctx, a, a.UserID, false)
		if err != nil || len(permissions) != 20 {
			t.Fatal("bootstrap permission set is incomplete")
		}
		assertErr(t, policy.Check(ctx, memberID, "user.read"), auth.ErrForbidden)
		assertErr(t, policy.Check(ctx, auth.Identity{UserID: a.UserID, TenantID: b.TenantID}, "user.read"), auth.ErrForbidden)
		_, err = rbac.Bootstrap(ctx, pool, rbac.BootstrapRequest{Approved: true, ExistingTenant: true, Code: "rbac-alpha", AdminUserID: a.UserID})
		assertErr(t, err, access.ErrConflict)
		_, err = rbac.Bootstrap(ctx, pool, rbac.BootstrapRequest{Approved: true, Name: "Rollback", Code: "rollback-bootstrap", AdminUserID: "ffffffff-ffff-4fff-8fff-ffffffffffff"})
		assertErr(t, err, access.ErrNotFound)
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE code='rollback-bootstrap'`).Scan(&count); err != nil || count != 0 {
			t.Fatal("failed bootstrap left a tenant")
		}
		result, err := rbac.Bootstrap(ctx, pool, rbac.BootstrapRequest{Approved: true, Name: "New Atomic Tenant", Code: "new-atomic", AdminUserID: a.UserID})
		if err != nil {
			t.Fatal(err)
		}
		if err := policy.Check(ctx, auth.Identity{UserID: a.UserID, TenantID: result.TenantID}, "user.read"); err != nil {
			t.Fatal("new tenant bootstrap missing membership or grants")
		}
	})
	t.Run("role CRUD and optimistic versions", func(t *testing.T) {
		r := role(t, "profile")
		_, err := rs.CreateRole(ctx, a, rbac.CreateRoleRequest{Name: "profile"})
		assertErr(t, err, access.ErrConflict)
		updated, err := rs.UpdateRole(ctx, a, r.ID, rbac.UpdateRoleRequest{Name: "profile-renamed", Description: "Updated", ExpectedVersion: r.Version})
		if err != nil || updated.Version == r.Version {
			t.Fatal("role update failed")
		}
		_, err = rs.UpdateRole(ctx, a, r.ID, rbac.UpdateRoleRequest{Name: "stale", ExpectedVersion: r.Version})
		assertErr(t, err, access.ErrConflict)
		assertErr(t, rs.DeleteRole(ctx, a, r.ID, rbac.DeleteRoleRequest{ExpectedVersion: r.Version}), access.ErrConflict)
		if err := rs.DeleteRole(ctx, a, r.ID, rbac.DeleteRoleRequest{ExpectedVersion: updated.Version}); err != nil {
			t.Fatal(err)
		}
		_, err = rs.GetRole(ctx, a, r.ID)
		assertErr(t, err, access.ErrNotFound)
	})
	t.Run("bootstrap cannot restore deliberately removed administrator grants", func(t *testing.T) {
		id, roleID := fixture("bootstrap-once")
		r, err := rs.GetRole(ctx, id, roleID)
		if err != nil {
			t.Fatal(err)
		}
		if err := rs.DeleteRole(ctx, id, roleID, rbac.DeleteRoleRequest{ExpectedVersion: r.Version}); err != nil {
			t.Fatal(err)
		}
		_, err = rbac.Bootstrap(ctx, pool, rbac.BootstrapRequest{Approved: true, ExistingTenant: true, Code: "bootstrap-once", AdminUserID: id.UserID})
		assertErr(t, err, access.ErrConflict)
		assertErr(t, policy.Check(ctx, id, "user.read"), auth.ErrForbidden)
	})
	t.Run("permission union multiple roles and immediate revocation", func(t *testing.T) {
		reader, writer := role(t, "reader"), role(t, "writer")
		grant(t, reader.ID, "user", "read")
		grant(t, writer.ID, "user", "read")
		grant(t, writer.ID, "user", "update")
		for _, r := range []rbac.Role{reader, writer} {
			if err := rs.ChangeUserRole(ctx, a, member.ID, r.ID, true); err != nil {
				t.Fatal(err)
			}
		}
		permissions, err := rs.Effective(ctx, a, member.ID, false)
		if err != nil || len(permissions) != 2 {
			t.Fatal("permission union was not distinct")
		}
		roles, err := rs.UserRoles(ctx, a, member.ID)
		if err != nil || len(roles) != 2 {
			t.Fatal("multiple user roles were not preserved")
		}
		if err := policy.Check(ctx, memberID, "user.update"); err != nil {
			t.Fatal(err)
		}
		if err := rs.ChangePermission(ctx, a, writer.ID, rbac.PermissionRequest{Resource: "user", Action: "update"}, false); err != nil {
			t.Fatal(err)
		}
		assertErr(t, policy.Check(ctx, memberID, "user.update"), auth.ErrForbidden)
		if err := rs.ChangeUserRole(ctx, a, member.ID, reader.ID, false); err != nil {
			t.Fatal(err)
		}
		if err := policy.Check(ctx, memberID, "user.read"); err != nil {
			t.Fatal("revoking one role removed another role's permission")
		}
		if err := rs.DeleteRole(ctx, a, writer.ID, rbac.DeleteRoleRequest{ExpectedVersion: writer.Version}); err != nil {
			t.Fatal(err)
		}
		assertErr(t, policy.Check(ctx, memberID, "user.read"), auth.ErrForbidden)
		permissions, err = rs.Effective(ctx, a, member.ID, false)
		if err != nil || len(permissions) != 0 {
			t.Fatal("deleted role still grants permissions")
		}
	})
	t.Run("cross tenant role and user grants return not found", func(t *testing.T) {
		_, err := rs.GetRole(ctx, a, bRole)
		assertErr(t, err, access.ErrNotFound)
		_, err = rs.UpdateRole(ctx, a, bRole, rbac.UpdateRoleRequest{Name: "forged", ExpectedVersion: strings.Repeat("0", 64)})
		assertErr(t, err, access.ErrNotFound)
		assertErr(t, rs.DeleteRole(ctx, a, bRole, rbac.DeleteRoleRequest{ExpectedVersion: strings.Repeat("0", 64)}), access.ErrNotFound)
		_, err = rs.RolePermissions(ctx, a, bRole)
		assertErr(t, err, access.ErrNotFound)
		assertErr(t, rs.ChangePermission(ctx, a, bRole, rbac.PermissionRequest{Resource: "user", Action: "read"}, true), access.ErrNotFound)
		assertErr(t, rs.ChangeUserRole(ctx, a, b.UserID, adminRole, true), access.ErrNotFound)
		assertErr(t, rs.ChangeUserRole(ctx, a, member.ID, bRole, true), access.ErrNotFound)
		_, err = rs.Effective(ctx, a, b.UserID, false)
		assertErr(t, err, access.ErrNotFound)
		if err := policy.Check(ctx, b, "user.read"); err != nil {
			t.Fatal("cross-tenant attempts damaged another tenant's grants")
		}
	})
	t.Run("delegation cannot escalate caller privileges", func(t *testing.T) {
		limited := role(t, "grant-manager")
		grant(t, limited.ID, "role_permission", "assign")
		grant(t, limited.ID, "user_role", "assign")
		if err := rs.ChangeUserRole(ctx, a, member.ID, limited.ID, true); err != nil {
			t.Fatal(err)
		}
		assertErr(t, rs.ChangePermission(ctx, memberID, limited.ID, rbac.PermissionRequest{Resource: "user", Action: "delete"}, true), auth.ErrForbidden)
		assertErr(t, rs.ChangeUserRole(ctx, memberID, member.ID, adminRole, true), auth.ErrForbidden)
		if err := rs.ChangeUserRole(ctx, a, member.ID, limited.ID, false); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("password reset and membership activation cannot bypass delegation", func(t *testing.T) {
		manager := role(t, "identity-manager")
		grant(t, manager.ID, "user", "update")
		grant(t, manager.ID, "membership", "update")
		if err := rs.ChangeUserRole(ctx, a, member.ID, manager.ID, true); err != nil {
			t.Fatal(err)
		}
		privileged := create(t, a, "privileged-target@example.test")
		if err := rs.ChangeUserRole(ctx, a, privileged.ID, adminRole, true); err != nil {
			t.Fatal(err)
		}
		password := "replacement-password"
		_, err := us.Update(ctx, memberID, privileged.ID, user.UpdateRequest{Password: &password, ExpectedUpdatedAt: privileged.UpdatedAt})
		assertErr(t, err, auth.ErrForbidden)
		var hash string
		if err := pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE id=$1`, privileged.ID).Scan(&hash); err != nil || !auth.VerifyPassword(hash, "integration-password") {
			t.Fatal("denied password reset changed credentials")
		}
		m, err := us.SetMembershipStatus(ctx, a, privileged.ID, user.MembershipStatusRequest{Status: "suspended", ExpectedUpdatedAt: privileged.Membership.UpdatedAt})
		if err != nil {
			t.Fatal(err)
		}
		_, err = us.SetMembershipStatus(ctx, memberID, privileged.ID, user.MembershipStatusRequest{Status: "active", ExpectedUpdatedAt: m.UpdatedAt})
		assertErr(t, err, auth.ErrForbidden)
		if _, err := us.SetMembershipStatus(ctx, a, privileged.ID, user.MembershipStatusRequest{Status: "active", ExpectedUpdatedAt: m.UpdatedAt}); err != nil {
			t.Fatal(err)
		}
		if _, err := us.Update(ctx, a, privileged.ID, user.UpdateRequest{Password: &password, ExpectedUpdatedAt: privileged.UpdatedAt}); err != nil {
			t.Fatal("authorized administrator password reset failed")
		}
		if err := rs.ChangeUserRole(ctx, a, member.ID, manager.ID, false); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("transaction rechecks permission after earlier successful check", func(t *testing.T) {
		limited := role(t, "pending-writer")
		grant(t, limited.ID, "user", "create")
		if err := rs.ChangeUserRole(ctx, a, member.ID, limited.ID, true); err != nil {
			t.Fatal(err)
		}
		if err := policy.Check(ctx, memberID, "user.create"); err != nil {
			t.Fatal(err)
		}
		bound := access.Bind(ctx, policy, "user.create")
		if err := rs.ChangeUserRole(ctx, a, member.ID, limited.ID, false); err != nil {
			t.Fatal(err)
		}
		_, err := user.NewRepository(pool).Create(bound, memberID, user.CreateRequest{Email: "revoked-before-write@example.test", FullName: "Denied"}, "not-used")
		assertErr(t, err, auth.ErrForbidden)
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE email='revoked-before-write@example.test'`).Scan(&count); err != nil || count != 0 {
			t.Fatal("revoked request committed a user")
		}
	})
	t.Run("unsupported historical grants remain inert and preserved", func(t *testing.T) {
		r := role(t, "legacy-grant")
		var permissionID string
		if err := pool.QueryRow(ctx, `INSERT INTO permissions(resource,action) VALUES('legacy','unhandled') RETURNING id::text`).Scan(&permissionID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO role_permissions(tenant_id,role_id,permission_id) VALUES($1,$2,$3)`, a.TenantID, r.ID, permissionID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO user_roles(tenant_id,user_id,role_id) VALUES($1,$2,$3)`, a.TenantID, member.ID, r.ID); err != nil {
			t.Fatal(err)
		}
		assertErr(t, policy.Check(ctx, memberID, "legacy.unhandled"), auth.ErrForbidden)
		permissions, err := rs.Effective(ctx, a, member.ID, false)
		if err != nil || len(permissions) != 0 {
			t.Fatal("unsupported historical permission was considered effective")
		}
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM role_permissions WHERE tenant_id=$1 AND role_id=$2`, a.TenantID, r.ID).Scan(&count); err != nil || count != 1 {
			t.Fatal("historical grant was modified")
		}
		if err := rs.DeleteRole(ctx, a, r.ID, rbac.DeleteRoleRequest{ExpectedVersion: r.Version}); err != nil {
			t.Fatal(err)
		}
	})
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	tokens, err := auth.NewTokens(strings.Repeat("s", 32), "rbac-integration", time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	as, err := auth.NewService(auth.NewRepository(pool), tokens, logger)
	if err != nil {
		t.Fatal(err)
	}
	router := server.NewRouter(pool, 5*time.Second, logger, auth.NewHandler(as, 5*time.Second, logger), tenant.NewHandler(ts, tokens, 5*time.Second), user.NewHandler(us, tokens, 5*time.Second), rbac.NewHandler(rs, tokens, 5*time.Second))
	call := func(t *testing.T, token, method, path string, payload any, want int) *httptest.ResponseRecorder {
		t.Helper()
		var body io.Reader
		if payload != nil {
			b, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			body = strings.NewReader(string(b))
		}
		req := httptest.NewRequest(method, path, body)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-ID", b.TenantID)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != want {
			t.Fatalf("%s %s: HTTP %d, expected %d (body withheld)", method, path, w.Code, want)
		}
		return w
	}
	login := func(t *testing.T, email, code string) string {
		t.Helper()
		w := call(t, "", "POST", "/api/v1/auth/login", auth.LoginRequest{Email: email, Password: "integration-password", TenantCode: code}, 200)
		var pair auth.TokenPair
		if err := json.Unmarshal(w.Body.Bytes(), &pair); err != nil || pair.AccessToken == "" {
			t.Fatal("login did not return access token")
		}
		return pair.AccessToken
	}
	adminToken, memberToken := login(t, "rbac-alpha@example.test", "rbac-alpha"), login(t, member.Email, "rbac-alpha")
	t.Run("ordinary member denied all eleven management routes", func(t *testing.T) {
		for _, route := range []struct{ method, path string }{
			{"GET", "/api/v1/tenant"}, {"PATCH", "/api/v1/tenant"}, {"PATCH", "/api/v1/tenant/status"},
			{"POST", "/api/v1/users"}, {"GET", "/api/v1/users"}, {"GET", "/api/v1/users/" + a.UserID}, {"PATCH", "/api/v1/users/" + a.UserID}, {"DELETE", "/api/v1/users/" + a.UserID},
			{"POST", "/api/v1/memberships"}, {"PATCH", "/api/v1/memberships/" + a.UserID}, {"DELETE", "/api/v1/memberships/" + a.UserID},
		} {
			call(t, memberToken, route.method, route.path, nil, 403)
		}
		call(t, memberToken, "POST", "/api/v1/roles", rbac.CreateRoleRequest{Name: "forged-admin"}, 403)
		call(t, memberToken, "PUT", "/api/v1/users/"+member.ID+"/roles/"+adminRole, nil, 403)
		call(t, "", "GET", "/api/v1/roles", nil, 401)
		call(t, "invalid", "GET", "/api/v1/users", nil, 401)
		w := call(t, memberToken, "GET", "/api/v1/me/permissions", nil, 200)
		var result []rbac.Permission
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || len(result) != 0 {
			t.Fatal("ordinary member unexpectedly has permissions")
		}
	})
	t.Run("admin HTTP role grants and revocation affect old JWT", func(t *testing.T) {
		w := call(t, adminToken, "POST", "/api/v1/roles", rbac.CreateRoleRequest{Name: "http-reader"}, 201)
		var r rbac.Role
		if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		call(t, adminToken, "POST", "/api/v1/roles/"+r.ID+"/permissions", rbac.PermissionRequest{Resource: "user", Action: "read"}, 204)
		call(t, adminToken, "PUT", "/api/v1/users/"+member.ID+"/roles/"+r.ID, nil, 204)
		call(t, memberToken, "GET", "/api/v1/users", nil, 200)
		call(t, memberToken, "GET", "/api/v1/users/"+b.UserID+"?tenant_id="+b.TenantID, nil, 404)
		call(t, memberToken, "GET", "/api/v1/tenant", nil, 403)
		call(t, adminToken, "GET", "/api/v1/users/"+member.ID+"/permissions", nil, 200)
		call(t, adminToken, "GET", "/api/v1/users/"+member.ID+"/roles", nil, 200)
		call(t, adminToken, "GET", "/api/v1/permissions", nil, 200)
		call(t, adminToken, "GET", "/api/v1/roles?page=1&page_size=2", nil, 200)
		call(t, adminToken, "GET", "/api/v1/roles/"+bRole, nil, 404)
		call(t, adminToken, "DELETE", "/api/v1/users/"+member.ID+"/roles/"+r.ID, nil, 204)
		call(t, memberToken, "GET", "/api/v1/users", nil, 403)
		call(t, adminToken, "DELETE", "/api/v1/roles/"+r.ID, rbac.DeleteRoleRequest{ExpectedVersion: r.Version}, 204)
	})
	t.Run("authorized administrator uses all eleven management routes", func(t *testing.T) {
		w := call(t, adminToken, "GET", "/api/v1/tenant", nil, 200)
		var v tenant.Tenant
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		w = call(t, adminToken, "PATCH", "/api/v1/tenant", tenant.UpdateRequest{Name: "Renamed Alpha", ExpectedUpdatedAt: v.UpdatedAt}, 200)
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		call(t, adminToken, "PATCH", "/api/v1/tenant/status", tenant.StatusRequest{Status: "active", ExpectedUpdatedAt: v.UpdatedAt}, 200)
		w = call(t, adminToken, "POST", "/api/v1/users", user.CreateRequest{Email: "http-created@example.test", FullName: "HTTP Created", Password: "integration-password"}, 201)
		var u user.User
		if err := json.Unmarshal(w.Body.Bytes(), &u); err != nil {
			t.Fatal(err)
		}
		call(t, adminToken, "GET", "/api/v1/users", nil, 200)
		call(t, adminToken, "GET", "/api/v1/users/"+u.ID, nil, 200)
		name := "Updated"
		w = call(t, adminToken, "PATCH", "/api/v1/users/"+u.ID, user.UpdateRequest{FullName: &name, ExpectedUpdatedAt: u.UpdatedAt}, 200)
		if err := json.Unmarshal(w.Body.Bytes(), &u); err != nil {
			t.Fatal(err)
		}
		call(t, adminToken, "DELETE", "/api/v1/users/"+u.ID, user.VersionRequest{ExpectedUpdatedAt: u.UpdatedAt}, 204)
		other := create(t, b, "http-attach@example.test")
		w = call(t, adminToken, "POST", "/api/v1/memberships", user.MembershipRequest{UserID: other.ID}, 201)
		var m user.Membership
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		w = call(t, adminToken, "PATCH", "/api/v1/memberships/"+other.ID, user.MembershipStatusRequest{Status: "suspended", ExpectedUpdatedAt: m.UpdatedAt}, 200)
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		call(t, adminToken, "DELETE", "/api/v1/memberships/"+other.ID, user.VersionRequest{ExpectedUpdatedAt: m.UpdatedAt}, 204)
	})
	t.Run("old JWT denied for suspended tenant membership and deleted user", func(t *testing.T) {
		id, _ := fixture("inactive-tenant")
		pair, _, err := tokens.Issue(id)
		if err != nil {
			t.Fatal(err)
		}
		v, err := ts.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ts.SetStatus(ctx, id, tenant.StatusRequest{Status: "suspended", ExpectedUpdatedAt: v.UpdatedAt}); err != nil {
			t.Fatal(err)
		}
		call(t, pair.AccessToken, "GET", "/api/v1/users", nil, 403)
		call(t, pair.AccessToken, "GET", "/api/v1/me/permissions", nil, 403)
		_, err = ts.SetStatus(ctx, id, tenant.StatusRequest{Status: "active", ExpectedUpdatedAt: v.UpdatedAt})
		assertErr(t, err, auth.ErrForbidden)
		u := create(t, a, "inactive-member@example.test")
		r := role(t, "inactive-reader")
		grant(t, r.ID, "user", "read")
		if err := rs.ChangeUserRole(ctx, a, u.ID, r.ID, true); err != nil {
			t.Fatal(err)
		}
		pair, _, err = tokens.Issue(auth.Identity{UserID: u.ID, TenantID: a.TenantID})
		if err != nil {
			t.Fatal(err)
		}
		call(t, pair.AccessToken, "GET", "/api/v1/users", nil, 200)
		m, err := us.SetMembershipStatus(ctx, a, u.ID, user.MembershipStatusRequest{Status: "suspended", ExpectedUpdatedAt: u.Membership.UpdatedAt})
		if err != nil {
			t.Fatal(err)
		}
		call(t, pair.AccessToken, "GET", "/api/v1/users", nil, 403)
		permissions, err := rs.Effective(ctx, a, u.ID, false)
		if err != nil || len(permissions) != 0 {
			t.Fatal("suspended target has effective permissions")
		}
		if _, err := us.SetMembershipStatus(ctx, a, u.ID, user.MembershipStatusRequest{Status: "active", ExpectedUpdatedAt: m.UpdatedAt}); err != nil {
			t.Fatal(err)
		}
		if err := us.SoftDelete(ctx, a, u.ID, user.VersionRequest{ExpectedUpdatedAt: u.UpdatedAt}); err != nil {
			t.Fatal(err)
		}
		call(t, pair.AccessToken, "GET", "/api/v1/users", nil, 403)
		call(t, pair.AccessToken, "GET", "/api/v1/me/permissions", nil, 403)
	})
	t.Run("audits contain grant relationships and failure rolls back", func(t *testing.T) {
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE tenant_id=$1 AND action='user_role.assign' AND metadata ? 'related_id'`, a.TenantID).Scan(&count); err != nil || count == 0 {
			t.Fatal("grant audit relationships missing")
		}
		if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_rbac_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('role.create','role_permission.assign','user_role.assign') THEN RAISE EXCEPTION 'test audit rejection'; END IF; RETURN NEW; END $$;
 CREATE TRIGGER reject_rbac_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_rbac_audit()`); err != nil {
			t.Fatal(err)
		}
		_, err := rs.CreateRole(ctx, a, rbac.CreateRoleRequest{Name: "audit-rollback"})
		if err == nil {
			t.Fatal("audit failure ignored")
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM roles WHERE tenant_id=$1 AND name='audit-rollback'`, a.TenantID).Scan(&count); err != nil || count != 0 {
			t.Fatal("audit failure left a partial role")
		}
		if err := rs.ChangeUserRole(ctx, a, member.ID, adminRole, true); err == nil {
			t.Fatal("grant audit failure ignored")
		}
		assertErr(t, policy.Check(ctx, memberID, "tenant.read"), auth.ErrForbidden)
	})
}
