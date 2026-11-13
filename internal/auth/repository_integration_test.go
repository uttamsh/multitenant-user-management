package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// This test operates only in a unique schema it creates, and removes that schema
// on cleanup. Public application tables and records are never modified.
func TestPostgresAuthentication(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dsn := os.Getenv("AUTH_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set AUTH_TEST_DATABASE_URL to run isolated-schema PostgreSQL integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("could not configure integration database")
	}
	defer admin.Close()
	var randomID string
	if err := admin.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&randomID); err != nil {
		t.Fatal("could not connect to integration database")
	}
	schema := "auth_test_" + HashRefresh(randomID)[:16]
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error("could not remove isolated integration schema")
		}
	}()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid integration database configuration")
	}
	// No fallback to application tables if a test relation is accidentally absent.
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.MaxConns = 12
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	migration, err := os.ReadFile(filepath.Join("..", "..", "migrations", "001_init.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(migration)); err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("integration-only-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `INSERT INTO tenants (id, name, code) VALUES ($1, 'Integration', 'auth-test')`, testIdentity.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `INSERT INTO users (id, email, password_hash, full_name) VALUES ($1, 'MixedCase@Example.test', $2, 'Integration')`, testIdentity.UserID, string(hash))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tenant_users (user_id, tenant_id) VALUES ($1, $2)`, testIdentity.UserID, testIdentity.TenantID); err != nil {
		t.Fatal(err)
	}
	repo := NewRepository(pool)
	credentials, err := repo.FindCredentials(ctx, "mixedcase@example.test", "auth-test")
	if err != nil || credentials.Identity != testIdentity || !VerifyPassword(credentials.PasswordHash, "integration-only-password") {
		t.Fatal("case-insensitive login lookup failed")
	}
	if _, err := repo.FindCredentials(ctx, "mixedcase@example.test", "other-tenant"); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("cross-tenant login accepted")
	}
	tokens := testTokens(t)
	newSession := func(t *testing.T) RefreshSession {
		t.Helper()
		_, session, err := tokens.Issue(testIdentity)
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.CreateSession(ctx, testIdentity, session); err != nil {
			t.Fatal(err)
		}
		return session
	}
	issue := func(id Identity) (RefreshSession, error) { _, session, err := tokens.Issue(id); return session, err }
	t.Run("concurrent single use", func(t *testing.T) {
		old := newSession(t)
		var successes atomic.Int32
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				err := repo.Rotate(ctx, old.Hash, issue)
				if err == nil {
					successes.Add(1)
				} else if !errors.Is(err, ErrUnauthorized) {
					t.Errorf("rotation failed: %v", err)
				}
			})
		}
		wg.Wait()
		if successes.Load() != 1 {
			t.Fatalf("successful rotations=%d, want 1", successes.Load())
		}
	})
	t.Run("rollback retains old token", func(t *testing.T) {
		old := newSession(t)
		_, err := pool.Exec(ctx, `INSERT INTO refresh_tokens (tenant_id,user_id,token_hash,expires_at) VALUES ($1,$2,'duplicate',$3)`, testIdentity.TenantID, testIdentity.UserID, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		err = repo.Rotate(ctx, old.Hash, func(Identity) (RefreshSession, error) {
			return RefreshSession{Hash: "duplicate", ExpiresAt: time.Now().Add(time.Hour)}, nil
		})
		if err == nil {
			t.Fatal("duplicate replacement should fail")
		}
		if err := repo.Rotate(ctx, old.Hash, issue); err != nil {
			t.Fatalf("failed transaction consumed old token: %v", err)
		}
	})
	t.Run("callback failure retains old token", func(t *testing.T) {
		old := newSession(t)
		failure := errors.New("issuance failed")
		if err := repo.Rotate(ctx, old.Hash, func(Identity) (RefreshSession, error) { return RefreshSession{}, failure }); !errors.Is(err, failure) {
			t.Fatal("issuance failure ignored")
		}
		if err := repo.Rotate(ctx, old.Hash, issue); err != nil {
			t.Fatal("issuance failure consumed old token")
		}
	})
	t.Run("expired and revoked", func(t *testing.T) {
		old := newSession(t)
		if err := repo.Revoke(ctx, old.Hash); err != nil {
			t.Fatal(err)
		}
		if err := repo.Rotate(ctx, old.Hash, issue); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("revoked token accepted")
		}
		old = newSession(t)
		if _, err := pool.Exec(ctx, `UPDATE refresh_tokens SET expires_at = NOW() - INTERVAL '1 minute' WHERE token_hash=$1`, old.Hash); err != nil {
			t.Fatal(err)
		}
		if err := repo.Rotate(ctx, old.Hash, issue); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("expired token accepted")
		}
		if err := repo.Revoke(ctx, old.Hash); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("expired token authenticated logout")
		}
	})
	for _, tc := range []struct{ name, disable, enable string }{
		{"deleted user", `UPDATE users SET deleted_at=NOW()`, `UPDATE users SET deleted_at=NULL`},
		{"suspended tenant", `UPDATE tenants SET status='suspended'`, `UPDATE tenants SET status='active'`},
		{"suspended membership", `UPDATE tenant_users SET status='suspended'`, `UPDATE tenant_users SET status='active'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := newSession(t)
			if _, err := pool.Exec(ctx, tc.disable); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := pool.Exec(ctx, tc.enable); err != nil {
					t.Error(err)
				}
			}()
			if _, err := repo.FindCredentials(ctx, "mixedcase@example.test", "auth-test"); !errors.Is(err, ErrUnauthorized) {
				t.Fatal("inactive account accepted login")
			}
			if err := repo.Rotate(ctx, old.Hash, issue); !errors.Is(err, ErrUnauthorized) {
				t.Fatal("inactive account accepted refresh")
			}
			if err := repo.CreateSession(ctx, testIdentity, old); !errors.Is(err, ErrUnauthorized) {
				t.Fatal("inactive account issued session")
			}
			if err := repo.Revoke(ctx, old.Hash); !errors.Is(err, ErrUnauthorized) {
				t.Fatal("inactive account authenticated logout")
			}
		})
	}
	t.Run("login audit transaction completeness", func(t *testing.T) {
		testLoginAuditTransaction(t, ctx, pool, repo, tokens)
	})
	t.Run("HTTP login refresh logout with PostgreSQL", func(t *testing.T) {
		var beforeCount, count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action IN ('auth.login.success','auth.login.failure')`).Scan(&beforeCount); err != nil {
			t.Fatal(err)
		}
		logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
		service, err := NewService(repo, tokens, logger)
		if err != nil {
			t.Fatal(err)
		}
		router := gin.New()
		NewHandler(service, 5*time.Second, logger).Register(router)
		call := func(path string, payload any, want int) *httptest.ResponseRecorder {
			t.Helper()
			body, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/"+path, strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != want {
				t.Fatalf("%s returned %d, want %d", path, w.Code, want)
			}
			return w
		}
		response := call("login", LoginRequest{Email: "  MIXEDCASE@example.test  ", Password: "integration-only-password", TenantCode: "auth-test"}, 200)
		var pair TokenPair
		if err := json.Unmarshal(response.Body.Bytes(), &pair); err != nil {
			t.Fatal(err)
		}
		if id, err := tokens.Validate(pair.AccessToken); err != nil || id != testIdentity {
			t.Fatal("HTTP access token has incorrect identity")
		}
		response = call("refresh", RefreshRequest{RefreshToken: pair.RefreshToken}, 200)
		call("refresh", RefreshRequest{RefreshToken: pair.RefreshToken}, 401)
		if err := json.Unmarshal(response.Body.Bytes(), &pair); err != nil {
			t.Fatal(err)
		}
		call("logout", RefreshRequest{RefreshToken: pair.RefreshToken}, 204)
		call("refresh", RefreshRequest{RefreshToken: pair.RefreshToken}, 401)
		call("login", LoginRequest{Email: "mixedcase@example.test", Password: "wrong", TenantCode: "auth-test"}, 401)
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action IN ('auth.login.success','auth.login.failure')`).Scan(&count); err != nil || count != beforeCount+2 {
			t.Fatal("HTTP login outcomes were not audited")
		}
	})
	t.Run("development seed opt-in and idempotency", func(t *testing.T) {
		// pgx Config.ConnString returns the original DSN; edits to
		// RuntimeParams are not serialized into it. Set the schema in the DSN
		// itself before passing it across a process boundary.
		childDSN := dsn
		if strings.Contains(dsn, "://") {
			u, err := url.Parse(dsn)
			if err != nil {
				t.Fatal("invalid integration database URL")
			}
			query := u.Query()
			query.Set("search_path", schema)
			u.RawQuery = query.Encode()
			childDSN = u.String()
		} else {
			childDSN += " search_path=" + schema
		}
		probe, err := pgxpool.New(ctx, childDSN)
		if err != nil {
			t.Fatal("could not configure isolated seed connection")
		}
		defer probe.Close()
		var currentSchema string
		if err := probe.QueryRow(ctx, "SELECT current_schema()").Scan(&currentSchema); err != nil || currentSchema != schema {
			t.Fatal("refusing to seed outside isolated test schema")
		}
		runSeed := func(optIn bool) error {
			args := []string{"scripts/seed-dev.sh"}
			if optIn {
				args = append(args, "--development")
			}
			command := exec.CommandContext(ctx, "sh", args...)
			command.Dir = filepath.Join("..", "..")
			command.Env = append(os.Environ(), "DATABASE_URL="+childDSN, "JWT_SECRET="+strings.Repeat("s", 32))
			// Seed diagnostics are deliberately sanitized, but do not echo them
			// from tests in case future changes introduce connection information.
			return command.Run()
		}
		if err := runSeed(false); err == nil {
			t.Fatal("seed ran without explicit development opt-in")
		}
		if err := runSeed(true); err != nil {
			t.Fatal("development seed failed in isolated schema")
		}
		first, err := repo.FindCredentials(ctx, "dev-auth@example.test", "dev-auth")
		if err != nil || !VerifyPassword(first.PasswordHash, "DevOnly-ChangeMe-2026!") {
			t.Fatal("development fixture login failed")
		}
		if err := runSeed(true); err != nil {
			t.Fatal("repeated development seed failed")
		}
		second, err := repo.FindCredentials(ctx, "dev-auth@example.test", "dev-auth")
		if err != nil || first != second {
			t.Fatal("seed changed existing development credentials")
		}
	})
}
