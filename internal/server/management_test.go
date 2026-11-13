package server

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/uttam/multitenant-user-management/internal/access"
	"github.com/uttam/multitenant-user-management/internal/auth"
	"github.com/uttam/multitenant-user-management/internal/tenant"
	"github.com/uttam/multitenant-user-management/internal/user"
)

func TestManagementRoutesFailClosed(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	tokens, err := auth.NewTokens(strings.Repeat("s", 32), "test", time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pair, _, err := tokens.Issue(auth.Identity{UserID: "11111111-1111-4111-8111-111111111111", TenantID: "22222222-2222-4222-8222-222222222222"})
	if err != nil {
		t.Fatal(err)
	}
	r := NewRouter(nil, time.Second, logger, tenant.NewHandler(tenant.NewService(nil, access.DenyAll{}), tokens, time.Second), user.NewHandler(user.NewService(nil, access.DenyAll{}), tokens, time.Second))
	for _, route := range []struct{ method, path string }{
		{"GET", "/api/v1/tenant"}, {"PATCH", "/api/v1/tenant"}, {"PATCH", "/api/v1/tenant/status"},
		{"GET", "/api/v1/users"}, {"POST", "/api/v1/users"}, {"GET", "/api/v1/users/11111111-1111-4111-8111-111111111111"}, {"PATCH", "/api/v1/users/11111111-1111-4111-8111-111111111111"}, {"DELETE", "/api/v1/users/11111111-1111-4111-8111-111111111111"},
		{"POST", "/api/v1/memberships"}, {"PATCH", "/api/v1/memberships/11111111-1111-4111-8111-111111111111"}, {"DELETE", "/api/v1/memberships/11111111-1111-4111-8111-111111111111"},
	} {
		for _, authorization := range []string{"", "Bearer invalid", "Bearer " + pair.AccessToken} {
			req := httptest.NewRequest(route.method, route.path+"?tenant_id=forged", strings.NewReader(`{"tenant_id":"forged"}`))
			req.Header.Set("Authorization", authorization)
			req.Header.Set("X-Tenant-ID", "forged")
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			want := 401
			if authorization == "Bearer "+pair.AccessToken {
				want = 403
			}
			if w.Code != want {
				t.Fatalf("%s %s: got %d want %d", route.method, route.path, w.Code, want)
			}
		}
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/tenants", nil))
	if w.Code != 404 {
		t.Fatal("tenant registration route must not exist")
	}
}
