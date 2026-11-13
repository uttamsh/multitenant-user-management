package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var testIdentity = Identity{UserID: "11111111-1111-4111-8111-111111111111", TenantID: "22222222-2222-4222-8222-222222222222"}

func testTokens(t *testing.T) *Tokens {
	t.Helper()
	tokens, err := NewTokens(strings.Repeat("s", 32), "test-issuer", time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tokens
}

func TestTokensIssueAndValidate(t *testing.T) {
	tokens := testTokens(t)
	pair, session, err := tokens.Issue(testIdentity)
	if err != nil {
		t.Fatal(err)
	}
	id, err := tokens.Validate(pair.AccessToken)
	if err != nil || id != testIdentity {
		t.Fatalf("unexpected identity or validation error: %v", err)
	}
	if !validRefresh(pair.RefreshToken) || session.Hash != HashRefresh(pair.RefreshToken) || len(session.Hash) != 64 || session.Hash == pair.RefreshToken || pair.ExpiresIn != 60 || pair.TokenType != "Bearer" {
		t.Fatal("invalid token pair or refresh digest")
	}
	if remaining := time.Until(session.ExpiresAt); remaining < 59*time.Minute || remaining > time.Hour {
		t.Fatal("incorrect refresh expiry")
	}
	second, _, err := tokens.Issue(testIdentity)
	if err != nil || second.RefreshToken == pair.RefreshToken || second.AccessToken == pair.AccessToken {
		t.Fatal("tokens must be unique per issuance")
	}
}

func TestTokenValidationRejectsInvalidClaimsAndSignatures(t *testing.T) {
	tokens := testTokens(t)
	cases := []struct {
		name   string
		mutate func(jwt.MapClaims)
	}{
		{"missing subject", func(c jwt.MapClaims) { delete(c, "sub") }},
		{"invalid subject", func(c jwt.MapClaims) { c["sub"] = "invalid" }},
		{"missing tenant", func(c jwt.MapClaims) { delete(c, "tenant_id") }},
		{"invalid tenant", func(c jwt.MapClaims) { c["tenant_id"] = "not-a-uuid" }},
		{"zero tenant", func(c jwt.MapClaims) { c["tenant_id"] = "00000000-0000-0000-0000-000000000000" }},
		{"missing issuer", func(c jwt.MapClaims) { delete(c, "iss") }},
		{"wrong issuer", func(c jwt.MapClaims) { c["iss"] = "another-issuer" }},
		{"missing expiry", func(c jwt.MapClaims) { delete(c, "exp") }},
		{"expired", func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Minute).Unix() }},
		{"missing issued at", func(c jwt.MapClaims) { delete(c, "iat") }},
		{"future issued at", func(c jwt.MapClaims) { c["iat"] = time.Now().Add(time.Hour).Unix() }},
		{"missing JWT ID", func(c jwt.MapClaims) { delete(c, "jti") }},
		{"empty JWT ID", func(c jwt.MapClaims) { c["jti"] = " " }},
		{"not yet valid", func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(time.Hour).Unix() }},
		{"invalid lifetime", func(c jwt.MapClaims) {
			c["exp"] = time.Now().Add(-time.Hour).Unix()
			c["iat"] = time.Now().Add(-time.Minute).Unix()
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{"sub": testIdentity.UserID, "tenant_id": testIdentity.TenantID, "iss": "test-issuer", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "jti": "test-id"}
			tc.mutate(claims)
			raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(tokens.secret)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tokens.Validate(raw); err == nil {
				t.Fatal("invalid claims were accepted")
			}
		})
	}
	for _, method := range []jwt.SigningMethod{jwt.SigningMethodHS384, jwt.SigningMethodNone} {
		var key any = tokens.secret
		if method == jwt.SigningMethodNone {
			key = jwt.UnsafeAllowNoneSignatureType
		}
		raw, err := jwt.NewWithClaims(method, jwt.MapClaims{"iss": "test-issuer"}).SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tokens.Validate(raw); err == nil {
			t.Fatal("unexpected signing algorithm accepted")
		}
	}
	other, _ := NewTokens(strings.Repeat("x", 32), "test-issuer", time.Minute, time.Hour)
	pair, _, _ := other.Issue(testIdentity)
	for _, raw := range []string{"", "malformed", pair.AccessToken, strings.Repeat("x", 4097)} {
		if _, err := tokens.Validate(raw); err == nil {
			t.Fatal("invalid signature or token accepted")
		}
	}
}

func TestNewTokensRejectsUnsafeSettings(t *testing.T) {
	for _, tc := range []struct {
		secret, issuer  string
		access, refresh time.Duration
	}{
		{"short", "test", time.Minute, time.Hour},
		{strings.Repeat(" ", 32), "test", time.Minute, time.Hour},
		{strings.Repeat("s", 32), "", time.Minute, time.Hour},
		{strings.Repeat("s", 32), "test", 2 * time.Hour, 3 * time.Hour},
		{strings.Repeat("s", 32), "test", time.Minute, time.Second},
	} {
		if _, err := NewTokens(tc.secret, tc.issuer, tc.access, tc.refresh); err == nil {
			t.Fatal("unsafe settings accepted")
		}
	}
}
