package auth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

type memoryRepository struct {
	mu                 sync.Mutex
	credentials        Credentials
	findErr            error
	createErr          error
	auditErr           error
	failureAuditErr    error
	successIdentities  []Identity
	failureContextErr  error
	failureHasDeadline bool
	sessions           map[string]bool
	actions            []string
	lastEmail          string
}

func (r *memoryRepository) FindCredentials(_ context.Context, email, _ string) (Credentials, error) {
	r.lastEmail = email
	return r.credentials, r.findErr
}
func (r *memoryRepository) CreateSession(_ context.Context, id Identity, s RefreshSession) error {
	if r.createErr != nil {
		return r.createErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.auditErr != nil {
		return r.auditErr
	}
	r.sessions[s.Hash] = true
	r.actions = append(r.actions, "auth.login.success")
	r.successIdentities = append(r.successIdentities, id)
	return nil
}
func (r *memoryRepository) Rotate(_ context.Context, hash string, issue func(Identity) (RefreshSession, error)) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.sessions[hash] {
		return ErrUnauthorized
	}
	s, err := issue(r.credentials.Identity)
	if err != nil {
		return err
	}
	r.sessions[hash] = false
	r.sessions[s.Hash] = true
	return nil
}
func (r *memoryRepository) Revoke(_ context.Context, hash string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.sessions[hash] {
		return ErrUnauthorized
	}
	r.sessions[hash] = false
	return nil
}
func (r *memoryRepository) AuditLoginFailure(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failureContextErr = ctx.Err()
	_, r.failureHasDeadline = ctx.Deadline()
	if r.failureAuditErr != nil {
		return r.failureAuditErr
	}
	r.actions = append(r.actions, "auth.login.failure")
	return nil
}

func testService(t *testing.T) (*Service, *memoryRepository) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("test-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	repo := &memoryRepository{credentials: Credentials{Identity: testIdentity, PasswordHash: string(hash)}, sessions: make(map[string]bool)}
	s, err := NewService(repo, testTokens(t), slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return s, repo
}

func TestVerifyPassword(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(string(hash), "correct") {
		t.Fatal("valid password rejected")
	}
	for _, p := range []string{"incorrect", "", strings.Repeat("x", 73)} {
		if VerifyPassword(string(hash), p) {
			t.Fatal("invalid password accepted")
		}
	}
	if VerifyPassword("broken-hash", "correct") {
		t.Fatal("malformed bcrypt hash accepted")
	}
}

func TestLoginAndAudit(t *testing.T) {
	s, r := testService(t)
	pair, err := s.Login(context.Background(), LoginRequest{Email: "  User@Example.test  ", Password: "test-password", TenantCode: "dev"})
	if err != nil || pair.AccessToken == "" || !r.sessions[HashRefresh(pair.RefreshToken)] || r.lastEmail != "User@Example.test" {
		t.Fatalf("login failed: %v", err)
	}
	if len(r.actions) != 1 || r.actions[0] != "auth.login.success" {
		t.Fatal("missing success audit")
	}
	if len(r.successIdentities) != 1 || r.successIdentities[0] != testIdentity {
		t.Fatal("success audit must use the verified tenant and user identity")
	}
	_, err = s.Login(context.Background(), LoginRequest{Password: "wrong"})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatal("wrong password accepted")
	}
	r.findErr = ErrUnauthorized
	_, err = s.Login(context.Background(), LoginRequest{Password: "test-password"})
	if !errors.Is(err, ErrUnauthorized) || r.actions[len(r.actions)-1] != "auth.login.failure" {
		t.Fatal("unknown user must return identical authentication error and be audited")
	}
	r.findErr = nil
	r.createErr = ErrUnauthorized
	if _, err := s.Login(context.Background(), LoginRequest{Password: "test-password"}); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("user invalidated before issuance must fail")
	}
}

func TestLoginPersistenceFailureReturnsNoCredentials(t *testing.T) {
	for _, stage := range []string{"session/commit", "audit"} {
		t.Run(stage, func(t *testing.T) {
			s, r := testService(t)
			failure := errors.New("required persistence failed")
			if stage == "audit" {
				r.auditErr = failure
			} else {
				r.createErr = failure
			}
			pair, err := s.Login(context.Background(), LoginRequest{Password: "test-password"})
			if !errors.Is(err, failure) || pair != (TokenPair{}) {
				t.Fatal("failed persistence returned usable credentials")
			}
			if len(r.sessions) != 0 || len(r.actions) != 0 {
				t.Fatal("failed persistence left a session or success audit")
			}
		})
	}
}

func TestFailedLoginAuditRemainsBestEffort(t *testing.T) {
	s, r := testService(t)
	var logs bytes.Buffer
	s.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	r.failureAuditErr = errors.New("secret-driver-details")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, unknown := range []bool{false, true} {
		if unknown {
			r.findErr = ErrUnauthorized
		}
		pair, err := s.Login(ctx, LoginRequest{Email: "not-logged@example.test", Password: "wrong-not-logged"})
		if !errors.Is(err, ErrUnauthorized) || pair != (TokenPair{}) || len(r.sessions) != 0 || len(r.successIdentities) != 0 {
			t.Fatal("failure audit outage changed invalid-credential behavior")
		}
	}
	if r.failureContextErr != nil || !r.failureHasDeadline {
		t.Fatal("failure audit must be bounded and independent of request cancellation")
	}
	for _, value := range []string{"secret-driver-details", "not-logged@example.test", "wrong-not-logged"} {
		if strings.Contains(logs.String(), value) {
			t.Fatal("failure audit logging disclosed sensitive input")
		}
	}
}

func TestRefreshRotationAndLogout(t *testing.T) {
	s, r := testService(t)
	first, session, err := s.tokens.Issue(testIdentity)
	if err != nil {
		t.Fatal(err)
	}
	r.sessions[session.Hash] = true
	var success atomic.Int32
	var wg sync.WaitGroup
	var next TokenPair
	for range 8 {
		wg.Go(func() {
			pair, err := s.Refresh(context.Background(), first.RefreshToken)
			if err == nil {
				next = pair
				success.Add(1)
			} else if !errors.Is(err, ErrUnauthorized) {
				t.Errorf("unexpected refresh error: %v", err)
			}
		})
	}
	wg.Wait()
	if success.Load() != 1 || next.RefreshToken == first.RefreshToken {
		t.Fatal("refresh token must be single-use and rotate")
	}
	if _, err := s.Refresh(context.Background(), first.RefreshToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("reused token accepted")
	}
	if err := s.Logout(context.Background(), next.RefreshToken); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Refresh(context.Background(), next.RefreshToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("revoked token accepted")
	}
	if err := s.Logout(context.Background(), next.RefreshToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("revoked token authenticated logout")
	}
	if _, err := s.Refresh(context.Background(), "malformed"); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("malformed token accepted")
	}
}
