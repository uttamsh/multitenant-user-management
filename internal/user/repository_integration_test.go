package user_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/uttam/multitenant-user-management/internal/access"
	"github.com/uttam/multitenant-user-management/internal/auth"
	"github.com/uttam/multitenant-user-management/internal/tenant"
	"github.com/uttam/multitenant-user-management/internal/user"
	"golang.org/x/crypto/bcrypt"
)

// This Phase 3 fixture bypasses RBAC to isolate repository lifecycle tests.
// Phase 4 tests exercise the real production policy separately.
type allowTest struct{}

func (allowTest) Check(context.Context, auth.Identity, string) error { return nil }

func isolatedDatabase(t *testing.T, ctx context.Context) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("PHASE3_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set PHASE3_TEST_DATABASE_URL for isolated-schema integration tests")
	}
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("invalid integration database configuration")
	}
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	schema := "phase3_test_" + hex.EncodeToString(random[:])
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close()
		t.Fatal("could not create isolated integration schema")
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error("isolated schema cleanup failed")
		}
		admin.Close()
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid integration database configuration")
	}
	// Exclude public entirely: missing test tables can never fall back to app data.
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.MaxConns = 16
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
		t.Fatal("migration files missing")
	}
	for _, file := range files {
		sql, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("isolated migration %s failed: %v", filepath.Base(file), err)
		}
	}
	return pool
}

func TestPostgresPhase3(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := isolatedDatabase(t, ctx)
	tr := tenant.NewRepository(pool)
	ts := tenant.NewService(tr, allowTest{})
	ur := user.NewRepository(pool)
	us := user.NewService(ur, allowTest{})
	bootstrap := func(code string) auth.Identity {
		t.Helper()
		v, err := ts.Provision(ctx, tenant.CreateRequest{Name: code, Code: code})
		if err != nil {
			t.Fatal(err)
		}
		hash, err := bcrypt.GenerateFromPassword([]byte("integration-password"), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		var uid string
		if err := pool.QueryRow(ctx, `INSERT INTO users(email,full_name,password_hash) VALUES($1,'Actor',$2) RETURNING id::text`, code+"@example.test", string(hash)).Scan(&uid); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO tenant_users(tenant_id,user_id) VALUES($1,$2)`, v.ID, uid); err != nil {
			t.Fatal(err)
		}
		return auth.Identity{UserID: uid, TenantID: v.ID}
	}
	a, b := bootstrap("alpha"), bootstrap("beta")
	create := func(t *testing.T, id auth.Identity, email string) user.User {
		t.Helper()
		u, err := us.Create(ctx, id, user.CreateRequest{Email: email, FullName: "Test User", Password: "integration-password"})
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	version := func(u user.User) user.VersionRequest { return user.VersionRequest{ExpectedUpdatedAt: u.UpdatedAt} }
	assertErr := func(t *testing.T, err, want error) {
		t.Helper()
		if !errors.Is(err, want) {
			t.Fatalf("got error %v; want %v", err, want)
		}
	}
	t.Run("tenant update status and suspended access", func(t *testing.T) {
		v, err := ts.Get(ctx, a)
		if err != nil || v.ID != a.TenantID {
			t.Fatal("wrong current tenant")
		}
		updated, err := ts.Update(ctx, a, tenant.UpdateRequest{Name: "Alpha Updated", ExpectedUpdatedAt: v.UpdatedAt})
		if err != nil {
			t.Fatal(err)
		}
		_, err = ts.Update(ctx, a, tenant.UpdateRequest{Name: "stale", ExpectedUpdatedAt: v.UpdatedAt})
		assertErr(t, err, access.ErrConflict)
		_, err = ts.Provision(ctx, tenant.CreateRequest{Name: "Duplicate", Code: "alpha"})
		assertErr(t, err, access.ErrConflict)
		suspended, err := ts.SetStatus(ctx, a, tenant.StatusRequest{Status: "suspended", ExpectedUpdatedAt: updated.UpdatedAt})
		if err != nil {
			t.Fatal(err)
		}
		_, err = us.List(ctx, a, user.ListQuery{Page: 1, PageSize: 20})
		assertErr(t, err, auth.ErrForbidden)
		_, err = us.Create(ctx, a, user.CreateRequest{Email: "blocked@example.test", FullName: "Blocked", Password: "integration-password"})
		assertErr(t, err, auth.ErrForbidden)
		if _, err := ts.SetStatus(ctx, a, tenant.StatusRequest{Status: "active", ExpectedUpdatedAt: suspended.UpdatedAt}); err != nil {
			t.Fatal(err)
		}
	})
	uA, uB := create(t, a, "isolation-a@example.test"), create(t, b, "isolation-b@example.test")
	t.Run("cross tenant resources return not found", func(t *testing.T) {
		_, err := us.Get(ctx, a, uB.ID)
		assertErr(t, err, access.ErrNotFound)
		name := "Forbidden"
		_, err = us.Update(ctx, a, uB.ID, user.UpdateRequest{FullName: &name, ExpectedUpdatedAt: uB.UpdatedAt})
		assertErr(t, err, access.ErrNotFound)
		assertErr(t, us.SoftDelete(ctx, a, uB.ID, version(uB)), access.ErrNotFound)
		_, err = us.SetMembershipStatus(ctx, a, uB.ID, user.MembershipStatusRequest{Status: "suspended", ExpectedUpdatedAt: uB.Membership.UpdatedAt})
		assertErr(t, err, access.ErrNotFound)
		assertErr(t, us.RemoveMembership(ctx, a, uB.ID, user.VersionRequest{ExpectedUpdatedAt: uB.Membership.UpdatedAt}), access.ErrNotFound)
		_, err = us.AddMembership(ctx, a, user.MembershipRequest{UserID: "ffffffff-ffff-4fff-8fff-ffffffffffff"})
		assertErr(t, err, access.ErrNotFound)
		_, err = us.Get(ctx, auth.Identity{UserID: b.UserID, TenantID: a.TenantID}, uA.ID)
		assertErr(t, err, auth.ErrForbidden)
	})
	t.Run("duplicate emails preserve global identity", func(t *testing.T) {
		_, err := us.Create(ctx, b, user.CreateRequest{Email: "ISOLATION-A@example.test", FullName: "Duplicate", Password: "another-password"})
		assertErr(t, err, access.ErrConflict)
		var hash string
		if err := pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE id=$1`, uA.ID).Scan(&hash); err != nil || !auth.VerifyPassword(hash, "integration-password") {
			t.Fatal("duplicate create altered password")
		}
		if _, err := us.Get(ctx, b, uA.ID); !errors.Is(err, access.ErrNotFound) {
			t.Fatal("duplicate create attached an existing user")
		}
		payload, _ := json.Marshal(uA)
		if strings.Contains(string(payload), "password") || strings.Contains(string(payload), hash) {
			t.Fatal("password material escaped response DTO")
		}
	})
	t.Run("pagination filtering and updates", func(t *testing.T) {
		p1 := create(t, a, "paging-1@example.test")
		create(t, a, "paging-2@example.test")
		page, err := us.List(ctx, a, user.ListQuery{Page: 1, PageSize: 1, Search: "paging-"})
		if err != nil || page.Total != 2 || len(page.Items) != 1 {
			t.Fatal("pagination count failed")
		}
		second, err := us.List(ctx, a, user.ListQuery{Page: 2, PageSize: 1, Search: "paging-"})
		if err != nil || len(second.Items) != 1 || second.Items[0].ID == page.Items[0].ID {
			t.Fatal("stable page ordering failed")
		}
		if _, err := us.SetMembershipStatus(ctx, a, p1.ID, user.MembershipStatusRequest{Status: "suspended", ExpectedUpdatedAt: p1.Membership.UpdatedAt}); err != nil {
			t.Fatal(err)
		}
		filtered, err := us.List(ctx, a, user.ListQuery{Page: 1, PageSize: 20, Search: "paging-", MembershipStatus: "suspended"})
		if err != nil || filtered.Total != 1 {
			t.Fatal("membership filter failed")
		}
		name, email, password := "Changed", "Updated@Example.test", "updated-password"
		updated, err := us.Update(ctx, a, p1.ID, user.UpdateRequest{FullName: &name, Email: &email, Password: &password, ExpectedUpdatedAt: p1.UpdatedAt})
		if err != nil || updated.Email != "updated@example.test" || updated.FullName != name || !updated.UpdatedAt.After(p1.UpdatedAt) {
			t.Fatal("user update failed")
		}
		var hash string
		if err := pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE id=$1`, p1.ID).Scan(&hash); err != nil || !auth.VerifyPassword(hash, password) {
			t.Fatal("updated password was not hashed")
		}
		_, err = us.Update(ctx, a, p1.ID, user.UpdateRequest{FullName: &name, ExpectedUpdatedAt: p1.UpdatedAt})
		assertErr(t, err, access.ErrConflict)
	})
	t.Run("soft delete retains rows and excludes user", func(t *testing.T) {
		u := create(t, a, "softdelete@example.test")
		if err := us.SoftDelete(ctx, a, u.ID, version(u)); err != nil {
			t.Fatal(err)
		}
		_, err := us.Get(ctx, a, u.ID)
		assertErr(t, err, access.ErrNotFound)
		p, err := us.List(ctx, a, user.ListQuery{Page: 1, PageSize: 20, Search: "softdelete"})
		if err != nil || p.Total != 0 {
			t.Fatal("deleted user appears in list")
		}
		_, err = us.AddMembership(ctx, b, user.MembershipRequest{UserID: u.ID})
		assertErr(t, err, access.ErrNotFound)
		var retained bool
		if err := pool.QueryRow(ctx, `SELECT deleted_at IS NOT NULL FROM users WHERE id=$1`, u.ID).Scan(&retained); err != nil || !retained {
			t.Fatal("user was physically deleted")
		}
		var leaked int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM tenant_users WHERE tenant_id=$1 AND user_id=$2`, b.TenantID, u.ID).Scan(&leaked); err != nil || leaked != 0 {
			t.Fatal("failed attachment was not rolled back")
		}
		_, err = us.Create(ctx, a, user.CreateRequest{Email: u.Email, FullName: "Reuse", Password: "integration-password"})
		assertErr(t, err, access.ErrConflict)
	})
	t.Run("multiple tenants membership lifecycle and token revocation", func(t *testing.T) {
		u := create(t, a, "shared@example.test")
		m, err := us.AddMembership(ctx, b, user.MembershipRequest{UserID: u.ID})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := us.Get(ctx, b, u.ID); err != nil {
			t.Fatal("shared membership lookup failed")
		}
		_, err = us.AddMembership(ctx, b, user.MembershipRequest{UserID: u.ID})
		assertErr(t, err, access.ErrConflict)
		name := "Global change"
		_, err = us.Update(ctx, a, u.ID, user.UpdateRequest{FullName: &name, ExpectedUpdatedAt: u.UpdatedAt})
		assertErr(t, err, access.ErrConflict)
		assertErr(t, us.SoftDelete(ctx, a, u.ID, version(u)), access.ErrConflict)
		ar := auth.NewRepository(pool)
		if err := ar.CreateSession(ctx, auth.Identity{UserID: u.ID, TenantID: a.TenantID}, auth.RefreshSession{Hash: "shared-alpha", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		if err := ar.CreateSession(ctx, auth.Identity{UserID: u.ID, TenantID: b.TenantID}, auth.RefreshSession{Hash: "shared-beta", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		suspended, err := us.SetMembershipStatus(ctx, b, u.ID, user.MembershipStatusRequest{Status: "suspended", ExpectedUpdatedAt: m.UpdatedAt})
		if err != nil {
			t.Fatal(err)
		}
		_, err = ar.FindCredentials(ctx, u.Email, "beta")
		assertErr(t, err, auth.ErrUnauthorized)
		if _, err := ar.FindCredentials(ctx, u.Email, "alpha"); err != nil {
			t.Fatal("other tenant login was affected")
		}
		var revoked bool
		if err := pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM refresh_tokens WHERE token_hash='shared-beta'`).Scan(&revoked); err != nil || !revoked {
			t.Fatal("suspension did not revoke scoped refresh token")
		}
		if err := pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM refresh_tokens WHERE token_hash='shared-alpha'`).Scan(&revoked); err != nil || revoked {
			t.Fatal("other tenant token was revoked")
		}
		active, err := us.SetMembershipStatus(ctx, b, u.ID, user.MembershipStatusRequest{Status: "active", ExpectedUpdatedAt: suspended.UpdatedAt})
		if err != nil {
			t.Fatal(err)
		}
		assertErr(t, us.RemoveMembership(ctx, b, u.ID, user.VersionRequest{ExpectedUpdatedAt: m.UpdatedAt}), access.ErrConflict)
		if err := us.RemoveMembership(ctx, b, u.ID, user.VersionRequest{ExpectedUpdatedAt: active.UpdatedAt}); err != nil {
			t.Fatal(err)
		}
		_, err = us.Get(ctx, b, u.ID)
		assertErr(t, err, access.ErrNotFound)
		if _, err := us.Get(ctx, a, u.ID); err != nil {
			t.Fatal("removal affected another tenant")
		}
		var removed bool
		if err := pool.QueryRow(ctx, `SELECT removed_at IS NOT NULL AND status='suspended' FROM tenant_users WHERE tenant_id=$1 AND user_id=$2`, b.TenantID, u.ID).Scan(&removed); err != nil || !removed {
			t.Fatal("membership history not retained")
		}
		if _, err := us.AddMembership(ctx, b, user.MembershipRequest{UserID: u.ID}); err != nil {
			t.Fatal("membership reattachment failed")
		}
		if err := pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM refresh_tokens WHERE token_hash='shared-beta'`).Scan(&revoked); err != nil || !revoked {
			t.Fatal("reattachment resurrected old token")
		}
	})
	t.Run("concurrent stale writes have one winner", func(t *testing.T) {
		u := create(t, a, "concurrent@example.test")
		var wg sync.WaitGroup
		results := make(chan error, 2)
		for _, name := range []string{"First", "Second"} {
			wg.Go(func() {
				_, err := us.Update(ctx, a, u.ID, user.UpdateRequest{FullName: &name, ExpectedUpdatedAt: u.UpdatedAt})
				results <- err
			})
		}
		wg.Wait()
		close(results)
		wins, conflicts := 0, 0
		for err := range results {
			if err == nil {
				wins++
			} else if errors.Is(err, access.ErrConflict) {
				conflicts++
			} else {
				t.Fatal(err)
			}
		}
		if wins != 1 || conflicts != 1 {
			t.Fatalf("wins=%d conflicts=%d", wins, conflicts)
		}
	})
	t.Run("suspended or removed actor cannot act with old JWT identity", func(t *testing.T) {
		c := bootstrap("blocked-actor")
		if _, err := pool.Exec(ctx, `UPDATE tenant_users SET status='suspended' WHERE tenant_id=$1 AND user_id=$2`, c.TenantID, c.UserID); err != nil {
			t.Fatal(err)
		}
		_, err := us.List(ctx, c, user.ListQuery{Page: 1, PageSize: 20})
		assertErr(t, err, auth.ErrForbidden)
		if _, err := pool.Exec(ctx, `UPDATE tenant_users SET removed_at=NOW() WHERE tenant_id=$1 AND user_id=$2`, c.TenantID, c.UserID); err != nil {
			t.Fatal(err)
		}
		_, err = ts.Get(ctx, c)
		assertErr(t, err, auth.ErrForbidden)
	})
	t.Run("concurrent duplicate creation has one winner", func(t *testing.T) {
		var wg sync.WaitGroup
		results := make(chan error, 2)
		for range 2 {
			wg.Go(func() {
				_, err := us.Create(ctx, a, user.CreateRequest{Email: "duplicate-race@example.test", FullName: "Concurrent", Password: "integration-password"})
				results <- err
			})
		}
		wg.Wait()
		close(results)
		wins, conflicts := 0, 0
		for err := range results {
			if err == nil {
				wins++
			} else if errors.Is(err, access.ErrConflict) {
				conflicts++
			} else {
				t.Fatal(err)
			}
		}
		if wins != 1 || conflicts != 1 {
			t.Fatalf("wins=%d conflicts=%d", wins, conflicts)
		}
	})
	t.Run("attachment and deletion cannot leave a deleted member", func(t *testing.T) {
		u := create(t, a, "attach-delete-race@example.test")
		var attachErr, deleteErr error
		var wg sync.WaitGroup
		wg.Go(func() { _, attachErr = us.AddMembership(ctx, b, user.MembershipRequest{UserID: u.ID}) })
		wg.Go(func() { deleteErr = us.SoftDelete(ctx, a, u.ID, version(u)) })
		wg.Wait()
		if attachErr == nil {
			assertErr(t, deleteErr, access.ErrConflict)
		} else if deleteErr == nil {
			assertErr(t, attachErr, access.ErrNotFound)
		} else {
			t.Fatalf("both operations failed: attachment=%v deletion=%v", attachErr, deleteErr)
		}
		var invalid int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM users u JOIN tenant_users tu ON tu.user_id=u.id WHERE u.id=$1 AND u.deleted_at IS NOT NULL AND tu.removed_at IS NULL`, u.ID).Scan(&invalid); err != nil || invalid != 0 {
			t.Fatal("attachment race created a live membership for deleted user")
		}
	})
	t.Run("removed memberships do not restore historical grants", func(t *testing.T) {
		u := create(t, a, "historical-grants@example.test")
		m, err := us.AddMembership(ctx, b, user.MembershipRequest{UserID: u.ID})
		if err != nil {
			t.Fatal(err)
		}
		var roleID string
		if err := pool.QueryRow(ctx, `INSERT INTO roles(tenant_id,name) VALUES($1,'historical') RETURNING id::text`, b.TenantID).Scan(&roleID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO user_roles(tenant_id,user_id,role_id) VALUES($1,$2,$3)`, b.TenantID, u.ID, roleID); err != nil {
			t.Fatal(err)
		}
		if err := us.RemoveMembership(ctx, b, u.ID, user.VersionRequest{ExpectedUpdatedAt: m.UpdatedAt}); err != nil {
			t.Fatal(err)
		}
		_, err = us.AddMembership(ctx, b, user.MembershipRequest{UserID: u.ID})
		assertErr(t, err, access.ErrConflict)
		var retained int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM user_roles WHERE tenant_id=$1 AND user_id=$2`, b.TenantID, u.ID).Scan(&retained); err != nil || retained != 1 {
			t.Fatal("membership removal erased role history")
		}
		_, err = auth.NewRepository(pool).FindCredentials(ctx, u.Email, "beta")
		assertErr(t, err, auth.ErrUnauthorized)
	})
	t.Run("HTTP uses JWT tenant and rejects tenant selectors", func(t *testing.T) {
		tokens, err := auth.NewTokens(strings.Repeat("s", 32), "integration", time.Minute, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		pair, _, err := tokens.Issue(a)
		if err != nil {
			t.Fatal(err)
		}
		router := gin.New()
		user.NewHandler(us, tokens, 5*time.Second).Register(router)
		tenant.NewHandler(ts, tokens, 5*time.Second).Register(router)
		call := func(method, path, body string, want int) {
			t.Helper()
			req := httptest.NewRequest(method, path, strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
			req.Header.Set("X-Tenant-ID", b.TenantID)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != want {
				t.Fatalf("%s %s got %d want %d", method, path, w.Code, want)
			}
			if strings.Contains(w.Body.String(), "password_hash") {
				t.Fatal("HTTP exposed hash")
			}
		}
		call(http.MethodGet, "/api/v1/users/"+uB.ID+"?tenant_id="+b.TenantID, "", 404)
		call(http.MethodGet, "/api/v1/users/invalid", "", 400)
		call(http.MethodGet, "/api/v1/users?page_size=101", "", 400)
		call(http.MethodGet, "/api/v1/users?tenant_id="+b.TenantID, "", 400)
		call(http.MethodPost, "/api/v1/users", `{"email":"injected@example.test","password":"integration-password","full_name":"Injected","tenant_id":"`+b.TenantID+`"}`, 400)
		call(http.MethodGet, "/api/v1/tenant", "", 200)
		call(http.MethodGet, "/api/v1/users?page=1&page_size=2&membership_status=active", "", 200)
	})
	t.Run("audit failure rolls back multi table operations", func(t *testing.T) {
		_, err := pool.Exec(ctx, `CREATE FUNCTION reject_test_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test audit failure'; END $$;
 CREATE TRIGGER reject_test_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_test_audit()`)
		if err != nil {
			t.Fatal(err)
		}
		_, err = us.Create(ctx, a, user.CreateRequest{Email: "audit-rollback@example.test", FullName: "Rollback", Password: "integration-password"})
		if err == nil {
			t.Fatal("audit failure was ignored")
		}
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE email='audit-rollback@example.test'`).Scan(&count); err != nil || count != 0 {
			t.Fatal("failed audit left partial user")
		}
		_, err = ts.Provision(ctx, tenant.CreateRequest{Name: "Rollback", Code: "rollback"})
		if err == nil {
			t.Fatal("tenant audit failure ignored")
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE code='rollback'`).Scan(&count); err != nil || count != 0 {
			t.Fatal("failed audit left tenant")
		}
	})
}
