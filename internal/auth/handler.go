package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/uttam/multitenant-user-management/internal/middleware"
)

type Handler struct {
	service *Service
	timeout time.Duration
	logger  *slog.Logger
}

func NewHandler(service *Service, timeout time.Duration, logger *slog.Logger) *Handler {
	return &Handler{service: service, timeout: timeout, logger: logger}
}

func (h *Handler) Register(r *gin.Engine) {
	g := r.Group("/api/v1/auth")
	g.Use(func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		ctx, cancel := context.WithTimeout(c.Request.Context(), h.timeout)
		defer cancel()
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	})
	g.POST("/login", h.login)
	g.POST("/refresh", h.refresh)
	g.POST("/logout", h.logout)
}

func decode(c *gin.Context, target any) bool {
	if c.ContentType() != "application/json" {
		middleware.Error(c, http.StatusBadRequest, "invalid_request", "A JSON request body is required")
		return false
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16*1024)
	d := json.NewDecoder(c.Request.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		middleware.Error(c, http.StatusBadRequest, "invalid_request", "Invalid JSON request")
		return false
	}
	if err := d.Decode(new(any)); err != io.EOF {
		middleware.Error(c, http.StatusBadRequest, "invalid_request", "Expected one JSON object")
		return false
	}
	return true
}

// login serves POST /api/v1/auth/login.
// @Summary Authenticate in a tenant
// @Description Requires a non-deleted user, active tenant and active membership. Unknown users, incorrect passwords and inactive accounts share the same 401. The refresh session and success audit (verified tenant, actor=user, target=user, DB timestamp) commit atomically before credentials are returned. Required persistence failures return sanitized 500 without tokens. Invalid-credential failure audits remain anonymous and best effort.
// @ID login
// @Tags Authentication
// @Produce json
// @Accept json
// @x-required-permission null
// @x-identity-state-required false
// @Param request body auth.LoginRequest true "One JSON object; unknown fields/extra JSON values rejected; max 16 KiB"
// @Success 200 {object} auth.TokenPair
// @Failure 400 {object} middleware.ErrorResponse "Invalid JSON, content type, body size, or required credential fields. Application body failures use 400, not 413/415."
// @Failure 401 {object} middleware.ErrorResponse "Invalid email/password/tenant combination or inactive account; account existence is not disclosed."
// @Failure 500 {object} middleware.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Router /api/v1/auth/login [post]
func (h *Handler) login(c *gin.Context) {
	var req LoginRequest
	if !decode(c, &req) {
		return
	}
	email := strings.TrimSpace(req.Email)
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email || len(email) > 255 || len(req.Password) == 0 || len(req.Password) > 72 || strings.TrimSpace(req.TenantCode) == "" || len(req.TenantCode) > 50 {
		middleware.Error(c, http.StatusBadRequest, "invalid_request", "Valid email, password (1–72 bytes), and tenant_code are required")
		return
	}
	pair, err := h.service.Login(c.Request.Context(), req)
	if err != nil {
		h.respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, pair)
}

// refresh serves POST /api/v1/auth/refresh.
// @Summary Atomically rotate a refresh credential
// @Description No access JWT required. Concurrent reuse has one winner; old credential is revoked atomically with replacement. Expired/revoked/inactive-account tokens return 401. A lost successful response cannot be retried using the old credential.
// @ID refresh
// @Tags Authentication
// @Produce json
// @Accept json
// @x-required-permission null
// @x-identity-state-required false
// @Param request body auth.RefreshRequest true "One JSON object; unknown fields/extra JSON values rejected; max 16 KiB"
// @Success 200 {object} auth.TokenPair
// @Failure 400 {object} middleware.ErrorResponse "Invalid JSON, content type, body size, or required credential fields. Application body failures use 400, not 413/415."
// @Failure 401 {object} middleware.ErrorResponse "Malformed, revoked or expired refresh credential, or an inactive account."
// @Failure 500 {object} middleware.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Router /api/v1/auth/refresh [post]
func (h *Handler) refresh(c *gin.Context) {
	var req RefreshRequest
	if !decode(c, &req) {
		return
	}
	if req.RefreshToken == "" {
		middleware.Error(c, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}
	pair, err := h.service.Refresh(c.Request.Context(), req.RefreshToken)
	if err != nil {
		h.respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, pair)
}

// logout serves POST /api/v1/auth/logout.
// @Summary Revoke the submitted refresh credential
// @Description No access JWT required. Does not revoke other sessions or an issued access JWT. Repeating logout with the revoked token returns 401.
// @ID logout
// @Tags Authentication
// @Produce json
// @Accept json
// @x-required-permission null
// @x-identity-state-required false
// @Param request body auth.RefreshRequest true "One JSON object; unknown fields/extra JSON values rejected; max 16 KiB"
// @Success 204 "No content"
// @Failure 400 {object} middleware.ErrorResponse "Invalid JSON, content type, body size, or required credential fields. Application body failures use 400, not 413/415."
// @Failure 401 {object} middleware.ErrorResponse "Malformed, revoked or expired refresh credential, or an inactive account."
// @Failure 500 {object} middleware.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Router /api/v1/auth/logout [post]
func (h *Handler) logout(c *gin.Context) {
	var req RefreshRequest
	if !decode(c, &req) {
		return
	}
	if req.RefreshToken == "" {
		middleware.Error(c, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}
	if err := h.service.Logout(c.Request.Context(), req.RefreshToken); err != nil {
		h.respondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *Handler) respondError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrUnauthorized):
		unauthorized(c)
	case errors.Is(err, ErrForbidden):
		middleware.Error(c, http.StatusForbidden, "forbidden", "Access forbidden")
	default:
		// Driver errors can contain SQL arguments. Never log their contents.
		h.logger.Error("authentication operation failed")
		middleware.Error(c, http.StatusInternalServerError, "internal_error", "An internal error occurred")
	}
}

func unauthorized(c *gin.Context) {
	c.Header("WWW-Authenticate", "Bearer")
	middleware.Error(c, http.StatusUnauthorized, "unauthorized", "Invalid or missing authentication")
}
