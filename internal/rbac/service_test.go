package rbac

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/uttam/multitenant-user-management/internal/access"
	"github.com/uttam/multitenant-user-management/internal/auth"
	"strings"
	"testing"
)

var testID = auth.Identity{UserID: "11111111-1111-4111-8111-111111111111", TenantID: "22222222-2222-4222-8222-222222222222"}

type boolRow struct {
	allowed bool
	err     error
}

func (r boolRow) Scan(values ...any) error {
	if r.err != nil {
		return r.err
	}
	*(values[0].(*bool)) = r.allowed
	return nil
}

type fakeQuery struct {
	allowed bool
	err     error
	sql     string
	args    []any
}

func (q *fakeQuery) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	q.sql, q.args = sql, args
	return boolRow{q.allowed, q.err}
}
func TestPolicyFailsClosedAndScopesQueries(t *testing.T) {
	ctx := context.Background()
	q := &fakeQuery{allowed: true}
	if err := check(ctx, q, testID, "user.read"); err != nil {
		t.Fatal(err)
	}
	if len(q.args) != 4 || q.args[0] != testID.TenantID || q.args[1] != testID.UserID || q.args[2] != "user" || q.args[3] != "read" || !strings.Contains(q.sql, "ur.tenant_id=$1") || !strings.Contains(q.sql, "tu.removed_at IS NULL") || !strings.Contains(q.sql, "u.deleted_at IS NULL") {
		t.Fatal("permission query omitted scope or current account checks")
	}
	q.allowed = false
	if err := check(ctx, q, testID, "user.read"); !errors.Is(err, auth.ErrForbidden) {
		t.Fatal("missing grant accepted")
	}
	failure := errors.New("database offline")
	q.err = failure
	if err := check(ctx, q, testID, "user.read"); !errors.Is(err, failure) {
		t.Fatal("database failure did not fail closed")
	}
	if err := check(ctx, nil, auth.Identity{}, "user.read"); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("missing identity accepted")
	}
	for _, action := range []string{"*", "user.*", "tenant:read", "unknown.read", "user.read.extra"} {
		if err := check(ctx, nil, testID, action); !errors.Is(err, auth.ErrForbidden) {
			t.Fatal("unsupported action accepted")
		}
	}
}

type allowUnit struct{}

func (allowUnit) Check(context.Context, auth.Identity, string) error { return nil }
func TestServiceAuthorizationAndValidation(t *testing.T) {
	s := NewService(nil, access.DenyAll{})
	ctx := context.Background()
	checks := []func() error{
		func() error { _, err := s.CreateRole(ctx, testID, CreateRoleRequest{}); return err },
		func() error { _, err := s.ListRoles(ctx, testID, 1, 20); return err },
		func() error { _, err := s.GetRole(ctx, testID, testID.UserID); return err },
		func() error { _, err := s.UpdateRole(ctx, testID, testID.UserID, UpdateRoleRequest{}); return err },
		func() error { return s.DeleteRole(ctx, testID, testID.UserID, DeleteRoleRequest{}) },
		func() error { _, err := s.Catalog(ctx, testID); return err },
		func() error { _, err := s.RolePermissions(ctx, testID, testID.UserID); return err },
		func() error { return s.ChangePermission(ctx, testID, testID.UserID, PermissionRequest{}, true) },
		func() error { return s.ChangePermission(ctx, testID, testID.UserID, PermissionRequest{}, false) },
		func() error { _, err := s.UserRoles(ctx, testID, testID.UserID); return err },
		func() error { return s.ChangeUserRole(ctx, testID, testID.UserID, testID.UserID, true) },
		func() error { return s.ChangeUserRole(ctx, testID, testID.UserID, testID.UserID, false) },
		func() error { _, err := s.Effective(ctx, testID, testID.UserID, false); return err },
	}
	for _, f := range checks {
		if err := f(); !errors.Is(err, auth.ErrForbidden) {
			t.Fatal("RBAC method bypassed authorization")
		}
	}
	s = NewService(nil, allowUnit{})
	if _, err := s.CreateRole(ctx, testID, CreateRoleRequest{Name: " "}); !errors.Is(err, access.ErrInvalid) {
		t.Fatal("invalid role accepted")
	}
	if _, err := s.ListRoles(ctx, testID, 1, 101); !errors.Is(err, access.ErrInvalid) {
		t.Fatal("unbounded list accepted")
	}
	if _, err := s.GetRole(ctx, testID, "invalid"); !errors.Is(err, access.ErrInvalid) {
		t.Fatal("invalid UUID accepted")
	}
	if err := s.ChangePermission(ctx, testID, testID.UserID, PermissionRequest{Resource: "user", Action: "*"}, true); !errors.Is(err, access.ErrInvalid) {
		t.Fatal("wildcard grant accepted")
	}
	if err := s.DeleteRole(ctx, testID, testID.UserID, DeleteRoleRequest{ExpectedVersion: "bad"}); !errors.Is(err, access.ErrInvalid) {
		t.Fatal("invalid version accepted")
	}
}
func TestCatalogAndVersions(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range Catalog() {
		if seen[p.Key()] || !supported(p.Resource, p.Action) {
			t.Fatal("invalid catalog")
		}
		seen[p.Key()] = true
	}
	if len(seen) != 20 {
		t.Fatalf("catalog size=%d, want 20", len(seen))
	}
	r := Role{ID: testID.UserID, Name: "reader"}
	r.setVersion()
	old := r.Version
	if !validVersion(old) {
		t.Fatal("invalid version digest")
	}
	r.Name = "writer"
	r.setVersion()
	if r.Version == old {
		t.Fatal("profile version did not change")
	}
}
func TestBootstrapRequiresExplicitApproval(t *testing.T) {
	if _, err := Bootstrap(context.Background(), nil, BootstrapRequest{}); !errors.Is(err, access.ErrInvalid) {
		t.Fatal("bootstrap ran without approval")
	}
	if _, err := Bootstrap(context.Background(), nil, BootstrapRequest{Approved: true, AdminUserID: "invalid"}); !errors.Is(err, access.ErrInvalid) {
		t.Fatal("bootstrap accepted invalid administrator")
	}
}
