package auth

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
	"github.com/jackc/pgx/v5/pgxpool"
)

// Called only by the existing unique-schema PostgreSQL harness. All DDL and
// fixture mutations below remain in that schema, with no public fallback.
func testLoginAuditTransaction(t *testing.T, ctx context.Context, pool *pgxpool.Pool, repo *PostgresRepository, tokens *Tokens) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	service, err := NewService(repo, tokens, logger)
	if err != nil {
		t.Fatal(err)
	}
	valid := LoginRequest{Email: "mixedcase@example.test", Password: "integration-only-password", TenantCode: "auth-test"}
	counts := func(t *testing.T) (sessions, successes int) {
		t.Helper()
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM refresh_tokens),
 (SELECT count(*) FROM audit_logs WHERE action='auth.login.success')`).Scan(&sessions, &successes); err != nil {
			t.Fatal(err)
		}
		return
	}

	t.Run("success has authenticated actor target timestamp and matching session", func(t *testing.T) {
		sessions, successes := counts(t)
		pair, err := service.Login(ctx, valid)
		if err != nil {
			t.Fatal("valid login failed")
		}
		if current, audits := counts(t); current != sessions+1 || audits != successes+1 {
			t.Fatal("login must commit exactly one session and one success audit")
		}
		var tenantID, actorID, targetID, targetType, auditJSON string
		var created time.Time
		if err := pool.QueryRow(ctx, `SELECT tenant_id::text,actor_id::text,target_id::text,target_type,created_at,to_jsonb(a)::text
 FROM audit_logs a WHERE action='auth.login.success' ORDER BY id DESC LIMIT 1`).Scan(&tenantID, &actorID, &targetID, &targetType, &created, &auditJSON); err != nil {
			t.Fatal(err)
		}
		if tenantID != testIdentity.TenantID || actorID != testIdentity.UserID || targetID != testIdentity.UserID || targetType != "user" || created.IsZero() {
			t.Fatal("success audit lacks correct tenant, authenticated actor, user target or timestamp")
		}
		for _, sensitive := range []string{pair.AccessToken, pair.RefreshToken, HashRefresh(pair.RefreshToken), valid.Password, valid.Email} {
			if sensitive == "" || strings.Contains(auditJSON, sensitive) {
				t.Fatal("success audit contains sensitive credentials or submitted identity")
			}
		}
		var matching bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM refresh_tokens
 WHERE token_hash=$1 AND user_id=$2 AND tenant_id=$3 AND revoked_at IS NULL AND expires_at>clock_timestamp())`, HashRefresh(pair.RefreshToken), testIdentity.UserID, testIdentity.TenantID).Scan(&matching); err != nil || !matching {
			t.Fatal("returned refresh credential has no matching committed session")
		}
		if id, err := tokens.Validate(pair.AccessToken); err != nil || id != testIdentity {
			t.Fatal("audit change altered JWT identity")
		}
		// A duplicate refresh hash fails before the audit and must not create a
		// standalone success record. The existing committed session remains intact.
		sessions, successes = counts(t)
		if err := repo.CreateSession(ctx, testIdentity, RefreshSession{Hash: HashRefresh(pair.RefreshToken), ExpiresAt: time.Now().Add(time.Hour)}); err == nil {
			t.Fatal("duplicate session unexpectedly committed")
		}
		if current, audits := counts(t); current != sessions || audits != successes {
			t.Fatal("session failure persisted an orphan audit or changed session count")
		}
	})

	t.Run("required success audit failure rolls back and returns no credentials", func(t *testing.T) {
		_, err := pool.Exec(ctx, `CREATE FUNCTION reject_login_success_audit() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN IF NEW.action='auth.login.success' THEN RAISE EXCEPTION 'sensitive-audit-driver-detail'; END IF; RETURN NEW; END $$;
 CREATE TRIGGER reject_login_success_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_login_success_audit()`)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := pool.Exec(cleanup, `DROP TRIGGER reject_login_success_audit ON audit_logs; DROP FUNCTION reject_login_success_audit()`); err != nil {
				t.Error("isolated audit failure trigger cleanup failed")
			}
		})
		sessions, successes := counts(t)
		pair, err := service.Login(ctx, valid)
		if err == nil || errors.Is(err, ErrUnauthorized) || pair != (TokenPair{}) {
			t.Fatal("audit failure must be internal error with no returned credentials")
		}
		if current, audits := counts(t); current != sessions || audits != successes {
			t.Fatal("required audit failure left a refresh session or success event")
		}
		router := gin.New()
		NewHandler(service, time.Second*5, logger).Register(router)
		body, err := json.Marshal(valid)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "access_token") || strings.Contains(response.Body.String(), "refresh_token") || strings.Contains(response.Body.String(), "sensitive") {
			t.Fatal("HTTP audit failure must return sanitized 500 without tokens")
		}
		if current, audits := counts(t); current != sessions || audits != successes {
			t.Fatal("HTTP audit failure left partial persistence")
		}
		for _, value := range []string{"sensitive-audit-driver-detail", valid.Password, valid.Email} {
			if strings.Contains(logs.String(), value) {
				t.Fatal("audit failure exposed driver details or credentials in logs")
			}
		}
	})

	t.Run("unknown and invalid credentials have anonymous failure events only", func(t *testing.T) {
		sessions, successes := counts(t)
		var before int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action='auth.login.failure'`).Scan(&before); err != nil {
			t.Fatal(err)
		}
		for _, input := range []LoginRequest{
			{Email: valid.Email, Password: "invalid-password", TenantCode: valid.TenantCode},
			{Email: "unknown@example.test", Password: valid.Password, TenantCode: valid.TenantCode},
			{Email: valid.Email, Password: valid.Password, TenantCode: "wrong-tenant"},
		} {
			pair, err := service.Login(ctx, input)
			if !errors.Is(err, ErrUnauthorized) || pair != (TokenPair{}) {
				t.Fatal("invalid login changed authentication semantics")
			}
		}
		var failures, attributed int
		if err := pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE tenant_id IS NOT NULL OR actor_id IS NOT NULL
 OR target_id IS NOT NULL OR target_type IS NOT NULL OR metadata<>'{}'::jsonb OR created_at IS NULL)
 FROM audit_logs WHERE action='auth.login.failure'`).Scan(&failures, &attributed); err != nil || failures != before+3 || attributed != 0 {
			t.Fatal("failure events must have timestamp but no asserted identity/target/request metadata")
		}
		if current, audits := counts(t); current != sessions || audits != successes {
			t.Fatal("invalid login persisted a session or success audit")
		}
	})
}
