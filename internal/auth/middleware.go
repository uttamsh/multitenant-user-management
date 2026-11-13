package auth

import (
	"context"
	"strings"

	"github.com/gin-gonic/gin"
)

type identityKey struct{}

// IdentityFromContext returns identity established by JWT validation. Protected
// services must scope every resource query to this tenant, returning 404 when a
// resource belongs to another tenant. Submitted tenant selectors are untrusted.
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(Identity)
	return id, ok
}

func Authenticate(tokens *Tokens) gin.HandlerFunc {
	return func(c *gin.Context) {
		values := c.Request.Header.Values("Authorization")
		if len(values) != 1 {
			unauthorized(c)
			return
		}
		parts := strings.Fields(values[0])
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			unauthorized(c)
			return
		}
		id, err := tokens.Validate(parts[1])
		if err != nil {
			unauthorized(c)
			return
		}
		c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), identityKey{}, id))
		c.Next()
	}
}
