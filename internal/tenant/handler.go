package tenant

import (
	"github.com/gin-gonic/gin"
	"github.com/uttam/multitenant-user-management/internal/auth"
	"github.com/uttam/multitenant-user-management/internal/httpapi"
	"time"
)

type Handler struct {
	service *Service
	tokens  *auth.Tokens
	timeout time.Duration
}

func NewHandler(service *Service, tokens *auth.Tokens, timeout time.Duration) *Handler {
	return &Handler{service, tokens, timeout}
}
func (h *Handler) Register(r *gin.Engine) {
	g := r.Group("/api/v1/tenant", auth.Authenticate(h.tokens), httpapi.Timeout(h.timeout))
	g.GET("", httpapi.Require(h.service.policy, "tenant.read"), h.get)
	g.PATCH("", httpapi.Require(h.service.policy, "tenant.update"), h.update)
	g.PATCH("/status", httpapi.Require(h.service.policy, "tenant.status"), h.status)
}

// get serves GET /api/v1/tenant.
// @Summary Get the current tenant
// @Description Requires active tenant, active non-removed membership and non-deleted actor. Permission: tenant:read.
// @ID getTenant
// @Tags Tenant
// @Produce json
// @Security BearerAuth
// @x-required-permission "tenant:read"
// @x-identity-state-required true
// @Success 200 {object} tenant.Tenant
// @Failure 401 {object} httpapi.ErrorResponse "Missing/invalid bearer JWT, or invalid login/refresh credentials. Authentication failures do not disclose account existence."
// @Failure 403 {object} httpapi.ErrorResponse "Valid JWT but insufficient permission, inactive tenant/membership, removed membership, deleted actor, or forbidden delegation/credential change. Authorization precedes target lookup and body validation."
// @Failure 500 {object} httpapi.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Router /api/v1/tenant [get]
func (h *Handler) get(c *gin.Context) {
	v, err := h.service.Get(c.Request.Context(), httpapi.Identity(c))
	httpapi.Reply(c, v, err, 200)
}

// update serves PATCH /api/v1/tenant.
// @Summary Update the current tenant name
// @Description Set expected_updated_at to the top-level updated_at from the latest GET /api/v1/tenant response. Copy the timestamp verbatim, preserving all fractional digits and microsecond precision; do not round to milliseconds, generate the current time, or use the Swagger example as a real version. A stale version returns 409; GET again before retrying. Requires active tenant, active non-removed membership and non-deleted actor. Permission: tenant:update. Changes and audits commit transactionally.
// @ID updateTenant
// @Tags Tenant
// @Produce json
// @Accept json
// @Security BearerAuth
// @x-required-permission "tenant:update"
// @x-identity-state-required true
// @Param request body tenant.UpdateRequest true "One JSON object; unknown fields/extra JSON values rejected; max 16 KiB"
// @Success 200 {object} tenant.Tenant
// @Failure 400 {object} httpapi.ErrorResponse "Invalid request: JSON/content type/body size, fields, UUID, pagination, supported permission pair, or required version. Application body failures use 400, not 413/415."
// @Failure 401 {object} httpapi.ErrorResponse "Missing/invalid bearer JWT, or invalid login/refresh credentials. Authentication failures do not disclose account existence."
// @Failure 403 {object} httpapi.ErrorResponse "Valid JWT but insufficient permission, inactive tenant/membership, removed membership, deleted actor, or forbidden delegation/credential change. Authorization precedes target lookup and body validation."
// @Failure 409 {object} httpapi.ErrorResponse "Stale tenant expected_updated_at. Database constraint, serialization or deadlock conflict. Reread before retrying."
// @Failure 500 {object} httpapi.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Router /api/v1/tenant [patch]
func (h *Handler) update(c *gin.Context) {
	var req UpdateRequest
	if !httpapi.Decode(c, &req) {
		return
	}
	v, err := h.service.Update(c.Request.Context(), httpapi.Identity(c), req)
	httpapi.Reply(c, v, err, 200)
}

// status serves PATCH /api/v1/tenant/status.
// @Summary Update current tenant status
// @Description Set expected_updated_at to the top-level updated_at from the latest GET /api/v1/tenant response. Copy the timestamp verbatim, preserving all fractional digits and microsecond precision; do not round to milliseconds, generate the current time, or use the Swagger example as a real version. A stale version returns 409; GET again before retrying. Suspension revokes tenant refresh tokens and blocks all subsequent protected HTTP requests. A suspended tenant cannot reactivate itself through this API. Requires active tenant, active non-removed membership and non-deleted actor. Permission: tenant:status. Changes and audits commit transactionally.
// @ID setTenantStatus
// @Tags Tenant
// @Produce json
// @Accept json
// @Security BearerAuth
// @x-required-permission "tenant:status"
// @x-identity-state-required true
// @Param request body tenant.StatusRequest true "One JSON object; unknown fields/extra JSON values rejected; max 16 KiB"
// @Success 200 {object} tenant.Tenant
// @Failure 400 {object} httpapi.ErrorResponse "Invalid request: JSON/content type/body size, fields, UUID, pagination, supported permission pair, or required version. Application body failures use 400, not 413/415."
// @Failure 401 {object} httpapi.ErrorResponse "Missing/invalid bearer JWT, or invalid login/refresh credentials. Authentication failures do not disclose account existence."
// @Failure 403 {object} httpapi.ErrorResponse "Valid JWT but insufficient permission, inactive tenant/membership, removed membership, deleted actor, or forbidden delegation/credential change. Authorization precedes target lookup and body validation."
// @Failure 409 {object} httpapi.ErrorResponse "Stale tenant expected_updated_at. Database constraint, serialization or deadlock conflict. Reread before retrying."
// @Failure 500 {object} httpapi.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Router /api/v1/tenant/status [patch]
func (h *Handler) status(c *gin.Context) {
	var req StatusRequest
	if !httpapi.Decode(c, &req) {
		return
	}
	v, err := h.service.SetStatus(c.Request.Context(), httpapi.Identity(c), req)
	httpapi.Reply(c, v, err, 200)
}
