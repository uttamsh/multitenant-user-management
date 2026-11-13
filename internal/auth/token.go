package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type Claims struct {
	TenantID string `json:"tenant_id"`
	jwt.RegisteredClaims
}

func (c Claims) Validate() error {
	if !validUUID(c.Subject) || !validUUID(c.TenantID) || strings.TrimSpace(c.ID) == "" || c.IssuedAt == nil || c.ExpiresAt == nil || !c.ExpiresAt.After(c.IssuedAt.Time) {
		return ErrUnauthorized
	}
	return nil
}

func validUUID(s string) bool {
	var id pgtype.UUID
	return len(s) == 36 && id.Scan(s) == nil && id.Valid && id.Bytes != [16]byte{}
}

type Tokens struct {
	secret     []byte
	issuer     string
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func NewTokens(secret, issuer string, accessTTL, refreshTTL time.Duration) (*Tokens, error) {
	if len(strings.TrimSpace(secret)) < 32 || strings.Contains(strings.ToUpper(secret), "REPLACE") || strings.TrimSpace(issuer) == "" || accessTTL < time.Second || accessTTL > time.Hour || refreshTTL <= accessTTL {
		return nil, errors.New("invalid JWT configuration: use a secret of at least 32 bytes, an issuer, access TTL between 1s and 1h, and a longer refresh TTL")
	}
	return &Tokens{secret: []byte(secret), issuer: issuer, accessTTL: accessTTL, refreshTTL: refreshTTL}, nil
}

func (t *Tokens) Issue(id Identity) (TokenPair, RefreshSession, error) {
	if !validUUID(id.UserID) || !validUUID(id.TenantID) {
		return TokenPair{}, RefreshSession{}, ErrUnauthorized
	}
	raw, err := randomToken()
	if err != nil {
		return TokenPair{}, RefreshSession{}, err
	}
	jti, err := randomToken()
	if err != nil {
		return TokenPair{}, RefreshSession{}, err
	}
	now := time.Now().UTC()
	claims := Claims{TenantID: id.TenantID, RegisteredClaims: jwt.RegisteredClaims{
		Subject: id.UserID, Issuer: t.issuer, ID: jti,
		IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(t.accessTTL)),
	}}
	access, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(t.secret)
	if err != nil {
		return TokenPair{}, RefreshSession{}, err
	}
	return TokenPair{AccessToken: access, RefreshToken: raw, TokenType: "Bearer", ExpiresIn: int64(t.accessTTL.Seconds())}, RefreshSession{Hash: HashRefresh(raw), ExpiresAt: now.Add(t.refreshTTL)}, nil
}

func (t *Tokens) Validate(raw string) (Identity, error) {
	if len(raw) > 4096 {
		return Identity{}, ErrUnauthorized
	}
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, ErrUnauthorized
		}
		return t.secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer(t.issuer), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil || !token.Valid {
		return Identity{}, ErrUnauthorized
	}
	return Identity{UserID: claims.Subject, TenantID: claims.TenantID}, nil
}

func randomToken() (string, error) {
	var data [32]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", errors.New("could not generate authentication token")
	}
	return base64.RawURLEncoding.EncodeToString(data[:]), nil
}

func HashRefresh(raw string) string {
	digest := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(digest[:])
}

func validRefresh(raw string) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	return err == nil && len(decoded) == 32 && len(raw) == 43
}
