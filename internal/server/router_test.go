package server

import (
	"bytes"
	"context"
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

type pingFunc func(context.Context) error

func (f pingFunc) Ping(ctx context.Context) error { return f(ctx) }

func TestOperationalRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name, method, path, code string
		pingErr                  error
		status                   int
		pings                    int
	}{
		{name: "liveness independent of database", method: "GET", path: "/health", pingErr: errors.New("offline"), status: 200},
		{name: "ready", method: "GET", path: "/ready", status: 200, pings: 1},
		{name: "database unavailable", method: "GET", path: "/ready", pingErr: errors.New("secret connection details"), status: 503, pings: 1, code: "database_unavailable"},
		{name: "unknown route", method: "GET", path: "/tenants", status: 404, code: "not_found"},
		{name: "unsupported method", method: "POST", path: "/health", status: 405, code: "method_not_allowed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			calls := 0
			r := NewRouter(pingFunc(func(ctx context.Context) error {
				calls++
				if _, ok := ctx.Deadline(); !ok {
					t.Error("database ping must have a deadline")
				}
				return tc.pingErr
			}), time.Second, slog.New(slog.NewJSONHandler(&logs, nil)))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path+"?token=secret", nil))
			if w.Code != tc.status || calls != tc.pings {
				t.Fatalf("status=%d pings=%d; want status=%d pings=%d", w.Code, calls, tc.status, tc.pings)
			}
			if tc.code != "" {
				var body struct {
					Error struct {
						Code string `json:"code"`
					} `json:"error"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Error.Code != tc.code {
					t.Fatalf("unexpected error body: %s", w.Body.String())
				}
			}
			if strings.Contains(w.Body.String(), "secret") || strings.Contains(logs.String(), "secret") {
				t.Fatal("response or logs leaked sensitive details")
			}
		})
	}
}

func TestReadinessTimeoutAndCancellation(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		var logs bytes.Buffer
		r := NewRouter(pingFunc(func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		}), 10*time.Millisecond, slog.New(slog.NewJSONHandler(&logs, nil)))
		ctx, cancel := context.WithCancel(context.Background())
		if canceled {
			cancel()
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ready", nil).WithContext(ctx))
		cancel()
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503, got %d", w.Code)
		}
	}
}

func TestRecoveryAndRequestLogging(t *testing.T) {
	var logs bytes.Buffer
	r := NewRouter(pingFunc(func(context.Context) error { panic("secret") }), time.Second, slog.New(slog.NewJSONHandler(&logs, nil)))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if w.Code != 500 || !strings.Contains(w.Body.String(), "internal_error") {
		t.Fatalf("unexpected panic response: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(logs.String(), "secret") || !strings.Contains(logs.String(), `"status":500`) {
		t.Fatalf("unexpected panic logs: %s", logs.String())
	}
}
