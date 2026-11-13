package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestAuthenticationMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tokens := testTokens(t)
	pair, _, err := tokens.Issue(testIdentity)
	if err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	r.POST("/protected", Authenticate(tokens), func(c *gin.Context) {
		id, ok := IdentityFromContext(c.Request.Context())
		if !ok || id != testIdentity {
			t.Error("trusted JWT identity missing or overwritten")
		}
		c.JSON(http.StatusOK, id)
	})
	for _, header := range []string{"", "Bearer invalid", "Basic abc", "Bearer", "Bearer " + pair.AccessToken} {
		req := httptest.NewRequest(http.MethodPost, "/protected?tenant_id=attacker", strings.NewReader(`{"tenant_id":"attacker"}`))
		req.Header.Set("Authorization", header)
		req.Header.Set("X-Tenant-ID", "attacker")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		want := http.StatusUnauthorized
		if header == "Bearer "+pair.AccessToken {
			want = http.StatusOK
		}
		if w.Code != want {
			t.Fatalf("status=%d; want %d", w.Code, want)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/protected", nil)
	req.Header.Add("Authorization", "Bearer "+pair.AccessToken)
	req.Header.Add("Authorization", "Bearer "+pair.AccessToken)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatal("ambiguous authorization headers accepted")
	}
}

func TestAuthHandlers(t *testing.T) {
	s, repo := testService(t)
	var logs bytes.Buffer
	h := NewHandler(s, time.Second, slog.New(slog.NewJSONHandler(&logs, nil)))
	r := gin.New()
	h.Register(r)
	call := func(path, body string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/"+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}
	for _, body := range []string{`{`, `null`, `{}`, `{"email":"bad","password":"p","tenant_code":"t"}`, `{"email":"a@example.test","password":"p","tenant_code":"t","tenant_id":"forged"}`, `{} {}`, strings.Repeat(" ", 17000)} {
		if w := call("login", body); w.Code != 400 {
			t.Fatalf("invalid login request status=%d", w.Code)
		}
	}
	w := call("login", `{"email":"User@example.test","password":"test-password","tenant_code":"dev"}`)
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("login failed: status=%d", w.Code)
	}
	var pair TokenPair
	if err := json.Unmarshal(w.Body.Bytes(), &pair); err != nil {
		t.Fatal(err)
	}
	refreshBody, _ := json.Marshal(RefreshRequest{RefreshToken: pair.RefreshToken})
	w = call("refresh", string(refreshBody))
	if w.Code != 200 {
		t.Fatalf("refresh failed: %d", w.Code)
	}
	var rotated TokenPair
	if err := json.Unmarshal(w.Body.Bytes(), &rotated); err != nil {
		t.Fatal(err)
	}
	if w := call("refresh", string(refreshBody)); w.Code != 401 {
		t.Fatal("token reuse accepted")
	}
	logoutBody, _ := json.Marshal(RefreshRequest{RefreshToken: rotated.RefreshToken})
	if w := call("logout", string(logoutBody)); w.Code != 204 {
		t.Fatal("logout failed")
	}
	if w := call("refresh", string(logoutBody)); w.Code != 401 {
		t.Fatal("revoked token accepted")
	}
	for _, path := range []string{"refresh", "logout"} {
		if w := call(path, `{}`); w.Code != 400 {
			t.Fatal("missing refresh credential must return 400")
		}
		if w := call(path, `{"refresh_token":"invalid"}`); w.Code != 401 {
			t.Fatal("invalid refresh credential must return 401")
		}
	}
	wrong := call("login", `{"email":"User@example.test","password":"incorrect","tenant_code":"dev"}`)
	repo.findErr = ErrUnauthorized
	unknown := call("login", `{"email":"missing@example.test","password":"incorrect","tenant_code":"dev"}`)
	if wrong.Code != 401 || unknown.Code != 401 || wrong.Body.String() != unknown.Body.String() {
		t.Fatal("login responses permit account enumeration")
	}
	repo.findErr = ErrForbidden
	if w := call("login", `{"email":"a@example.test","password":"p","tenant_code":"dev"}`); w.Code != 403 {
		t.Fatal("forbidden error must return 403")
	}
	repo.findErr = errors.New("secret-driver-details")
	if w := call("login", `{"email":"a@example.test","password":"p","tenant_code":"dev"}`); w.Code != 500 || strings.Contains(w.Body.String(), "secret") {
		t.Fatal("internal error response leaked details")
	}
	repo.findErr = nil
	repo.auditErr = errors.New("secret-audit-driver-details")
	before := len(repo.sessions)
	w = call("login", `{"email":"User@example.test","password":"test-password","tenant_code":"dev"}`)
	if w.Code != 500 || strings.Contains(w.Body.String(), "secret") || strings.Contains(w.Body.String(), "access_token") || strings.Contains(w.Body.String(), "refresh_token") || len(repo.sessions) != before {
		t.Fatal("required audit failure must return sanitized 500 without credentials or session")
	}
	if strings.Contains(logs.String(), "secret") || strings.Contains(logs.String(), "test-password") {
		t.Fatal("logs leaked credentials")
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{}`))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatal("request without JSON content type accepted")
	}
}
