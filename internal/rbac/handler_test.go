package rbac

import (
	"github.com/gin-gonic/gin"
	"github.com/uttam/multitenant-user-management/internal/access"
	"github.com/uttam/multitenant-user-management/internal/auth"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEveryRBACRouteRequiresAuthenticationAndAuthorization(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tokens, err := auth.NewTokens(strings.Repeat("s", 32), "test", time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pair, _, err := tokens.Issue(testID)
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	NewHandler(NewService(nil, access.DenyAll{}), tokens, time.Second).Register(router)
	for _, route := range []struct{ method, path string }{
		{"POST", "/api/v1/roles"}, {"GET", "/api/v1/roles"}, {"GET", "/api/v1/roles/" + testID.UserID}, {"PATCH", "/api/v1/roles/" + testID.UserID}, {"DELETE", "/api/v1/roles/" + testID.UserID},
		{"GET", "/api/v1/permissions"}, {"GET", "/api/v1/roles/" + testID.UserID + "/permissions"}, {"POST", "/api/v1/roles/" + testID.UserID + "/permissions"}, {"DELETE", "/api/v1/roles/" + testID.UserID + "/permissions"},
		{"GET", "/api/v1/users/" + testID.UserID + "/roles"}, {"PUT", "/api/v1/users/" + testID.UserID + "/roles/" + testID.UserID}, {"DELETE", "/api/v1/users/" + testID.UserID + "/roles/" + testID.UserID},
		{"GET", "/api/v1/users/" + testID.UserID + "/permissions"}, {"GET", "/api/v1/me/permissions"},
	} {
		for _, token := range []string{"", "invalid", pair.AccessToken} {
			req := httptest.NewRequest(route.method, route.path, nil)
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			req.Header.Set("X-Tenant-ID", testID.TenantID)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			want := 401
			if token == pair.AccessToken {
				want = 403
			}
			if w.Code != want {
				t.Fatalf("%s %s status=%d want %d", route.method, route.path, w.Code, want)
			}
		}
	}
}
