package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/uttam/multitenant-user-management/internal/access"
	"github.com/uttam/multitenant-user-management/internal/auth"
	"github.com/uttam/multitenant-user-management/internal/middleware"
)

// ErrorResponse aliases the shared wire DTO for handler documentation.
type ErrorResponse = middleware.ErrorResponse

func Decode(c *gin.Context, value any) bool {
	if c.ContentType() != "application/json" {
		Error(c, access.ErrInvalid)
		return false
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16*1024)
	d := json.NewDecoder(c.Request.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		Error(c, access.ErrInvalid)
		return false
	}
	if err := d.Decode(new(any)); err != io.EOF {
		Error(c, access.ErrInvalid)
		return false
	}
	return true
}

func Error(c *gin.Context, err error) {
	switch {
	case errors.Is(err, access.ErrInvalid):
		middleware.Error(c, 400, "invalid_request", "Invalid request")
	case errors.Is(err, auth.ErrUnauthorized):
		c.Header("WWW-Authenticate", "Bearer")
		middleware.Error(c, 401, "unauthorized", "Invalid or missing authentication")
	case errors.Is(err, auth.ErrForbidden):
		middleware.Error(c, 403, "forbidden", "Access forbidden")
	case errors.Is(err, access.ErrNotFound):
		middleware.Error(c, 404, "not_found", "Resource not found")
	case errors.Is(err, access.ErrConflict):
		middleware.Error(c, 409, "conflict", "Resource conflict or stale version")
	default:
		middleware.Error(c, 500, "internal_error", "An internal error occurred")
	}
}

func Require(policy access.Policy, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := auth.IdentityFromContext(c.Request.Context())
		if err := access.Check(c.Request.Context(), policy, id, action); err != nil {
			Error(c, err)
			return
		}
		c.Request = c.Request.WithContext(access.Bind(c.Request.Context(), policy, action))
		c.Next()
	}
}

func Timeout(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()
		c.Request = c.Request.WithContext(ctx)
		c.Header("Cache-Control", "no-store")
		c.Next()
	}
}

func Identity(c *gin.Context) auth.Identity {
	id, _ := auth.IdentityFromContext(c.Request.Context())
	return id
}

func Reply(c *gin.Context, result any, err error, status int) {
	if err != nil {
		Error(c, err)
		return
	}
	if status == http.StatusNoContent {
		c.Status(status)
		return
	}
	c.JSON(status, result)
}

func Pagination(c *gin.Context) (page, size int, err error) {
	page, size = 1, 20
	if v, ok := c.GetQuery("page"); ok {
		page, err = strconv.Atoi(v)
		if err != nil {
			return 0, 0, access.ErrInvalid
		}
	}
	if v, ok := c.GetQuery("page_size"); ok {
		size, err = strconv.Atoi(v)
		if err != nil {
			return 0, 0, access.ErrInvalid
		}
	}
	if page < 1 || page > 1000000 || size < 1 || size > 100 {
		return 0, 0, access.ErrInvalid
	}
	return page, size, nil
}
