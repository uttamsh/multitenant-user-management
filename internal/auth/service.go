package auth

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Service struct {
	repo      Repository
	tokens    *Tokens
	logger    *slog.Logger
	dummyHash string
}

func NewService(repo Repository, tokens *Tokens, logger *slog.Logger) (*Service, error) {
	// Unknown accounts still perform bcrypt verification to reduce timing leakage.
	dummy, err := bcrypt.GenerateFromPassword([]byte("dummy-password-never-used-for-login"), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return &Service{repo: repo, tokens: tokens, logger: logger, dummyHash: string(dummy)}, nil
}

func VerifyPassword(hash, password string) bool {
	return len(password) <= 72 && bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func (s *Service) Login(ctx context.Context, req LoginRequest) (TokenPair, error) {
	// PostgreSQL LOWER on both operands matches users_email_unique semantics.
	credentials, err := s.repo.FindCredentials(ctx, strings.TrimSpace(req.Email), strings.TrimSpace(req.TenantCode))
	if err != nil {
		_ = VerifyPassword(s.dummyHash, req.Password)
		if errors.Is(err, ErrUnauthorized) {
			s.auditFailure(ctx)
		}
		return TokenPair{}, err
	}
	if !VerifyPassword(credentials.PasswordHash, req.Password) {
		// The submitted identity has not authenticated and is not an audit actor.
		s.auditFailure(ctx)
		return TokenPair{}, ErrUnauthorized
	}
	pair, session, err := s.tokens.Issue(credentials.Identity)
	if err != nil {
		return TokenPair{}, err
	}
	if err = s.repo.CreateSession(ctx, credentials.Identity, session); err != nil {
		if errors.Is(err, ErrUnauthorized) {
			s.auditFailure(ctx)
		}
		return TokenPair{}, err
	}
	// CreateSession committed both the session and required success audit. Never
	// return locally generated credentials after a persistence/commit failure.
	return pair, nil
}

func (s *Service) Refresh(ctx context.Context, raw string) (TokenPair, error) {
	if !validRefresh(raw) {
		return TokenPair{}, ErrUnauthorized
	}
	var pair TokenPair
	err := s.repo.Rotate(ctx, HashRefresh(raw), func(id Identity) (RefreshSession, error) {
		var session RefreshSession
		var err error
		pair, session, err = s.tokens.Issue(id)
		return session, err
	})
	if err != nil {
		return TokenPair{}, err
	}
	return pair, nil
}

func (s *Service) Logout(ctx context.Context, raw string) error {
	if !validRefresh(raw) {
		return ErrUnauthorized
	}
	return s.repo.Revoke(ctx, HashRefresh(raw))
}

func (s *Service) auditFailure(ctx context.Context) {
	// A disconnected client should not suppress an audit record. This remains
	// best effort and bounded, and carries no submitted credentials or email.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := s.repo.AuditLoginFailure(ctx); err != nil {
		s.logger.Warn("authentication audit write failed", "action", "auth.login.failure")
	}
}
