package auth

import (
	"context"
	"errors"
	"time"
)

var (
	ErrUnauthorized = errors.New("invalid authentication")
	ErrForbidden    = errors.New("access forbidden")
)

// Identity is the internal/operator model.
// @Description Internal or operator-only Identity; not an additional HTTP endpoint.
type Identity struct {
	UserID   string `json:"user_id"`
	TenantID string `json:"tenant_id"`
}

// Credentials is the internal/operator model.
// @Description Internal or operator-only Credentials; not an additional HTTP endpoint.
type Credentials struct {
	Identity
	PasswordHash string
}

// LoginRequest is the LoginRequest DTO.
// @Description Wire model for LoginRequest.
type LoginRequest struct {
	// Bare email, trimmed; at most 255 UTF-8 bytes. Lookup uses PostgreSQL LOWER on both operands.
	Email string `json:"email" binding:"required" format:"email" minLength:"1" maxLength:"255" extensions:"x-max-bytes=255"`
	// 1–72 UTF-8 bytes; existing password, not a password-creation policy.
	Password string `json:"password" binding:"required" format:"password" extensions:"x-max-bytes=72"`
	// Trimmed, nonblank, case-sensitive existing tenant code; at most 50 UTF-8 bytes.
	TenantCode string `json:"tenant_code" binding:"required" minLength:"1" maxLength:"50" extensions:"x-max-bytes=50"`
}

// RefreshRequest is the RefreshRequest DTO.
// @Description Wire model for RefreshRequest.
type RefreshRequest struct {
	// Opaque token from the latest successful login/refresh. Issued tokens are 43-character unpadded base64url strings. Missing/empty input returns 400; malformed nonempty input or invalid credentials return 401.
	RefreshToken string `json:"refresh_token" binding:"required" format:"password" minLength:"1"`
}

// TokenPair is the TokenPair DTO.
// @Description Wire model for TokenPair.
type TokenPair struct {
	// Short-lived HS256 JWT; do not log.
	AccessToken string `json:"access_token" binding:"required"`
	// 256-bit opaque refresh credential; do not log.
	RefreshToken string `json:"refresh_token" binding:"required"`
	TokenType    string `json:"token_type" binding:"required" enums:"Bearer"`
	// Access lifetime in whole seconds; default 900.
	ExpiresIn int64 `json:"expires_in" binding:"required" format:"int64"`
}

// RefreshSession contains only the token digest, never the bearer credential.
// RefreshSession is the internal/operator model.
// @Description Internal or operator-only RefreshSession; not an additional HTTP endpoint.
type RefreshSession struct {
	Hash      string
	ExpiresAt time.Time
}

type Repository interface {
	FindCredentials(context.Context, string, string) (Credentials, error)
	CreateSession(context.Context, Identity, RefreshSession) error
	// Rotate locks and validates the old session, calls issue, then atomically
	// revokes the old token and inserts its replacement. Callback failure rolls back.
	Rotate(context.Context, string, func(Identity) (RefreshSession, error)) error
	Revoke(context.Context, string) error
	Audit(context.Context, string, *Identity) error
}
