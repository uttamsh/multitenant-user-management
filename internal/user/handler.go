package user

import (
	"github.com/gin-gonic/gin"
	"github.com/uttam/multitenant-user-management/internal/access"
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
	g := r.Group("/api/v1", auth.Authenticate(h.tokens), httpapi.Timeout(h.timeout))
	g.POST("/users", httpapi.Require(h.service.policy, "user.create"), h.create)
	g.GET("/users", httpapi.Require(h.service.policy, "user.read"), h.list)
	g.GET("/users/:user_id", httpapi.Require(h.service.policy, "user.read"), h.get)
	g.PATCH("/users/:user_id", httpapi.Require(h.service.policy, "user.update"), h.update)
	g.DELETE("/users/:user_id", httpapi.Require(h.service.policy, "user.delete"), h.remove)
	g.POST("/memberships", httpapi.Require(h.service.policy, "membership.create"), h.addMembership)
	g.PATCH("/memberships/:user_id", httpapi.Require(h.service.policy, "membership.update"), h.status)
	g.DELETE("/memberships/:user_id", httpapi.Require(h.service.policy, "membership.delete"), h.removeMembership)
}

// create serves POST /api/v1/users.
// @Summary Create a user and membership
// @Description Global email uniqueness includes soft-deleted users. Existing email never overwrites credentials or silently attaches a user. Requires active tenant, active non-removed membership and non-deleted actor. Permission: user:create. Changes and audits commit transactionally.
// @ID createUser
// @Tags Users
// @Produce json
// @Accept json
// @Security BearerAuth
// @x-required-permission "user:create"
// @x-identity-state-required true
// @Param request body user.CreateRequest true "One JSON object; unknown fields/extra JSON values rejected; max 16 KiB"
// @Success 201 {object} user.User
// @Failure 400 {object} httpapi.ErrorResponse "Invalid request: JSON/content type/body size, fields, UUID, pagination, supported permission pair, or required version. Application body failures use 400, not 413/415."
// @Failure 401 {object} httpapi.ErrorResponse "Missing/invalid bearer JWT, or invalid login/refresh credentials. Authentication failures do not disclose account existence."
// @Failure 403 {object} httpapi.ErrorResponse "Valid JWT but insufficient permission, inactive tenant/membership, removed membership, deleted actor, or forbidden delegation/credential change. Authorization precedes target lookup and body validation."
// @Failure 409 {object} httpapi.ErrorResponse "Duplicate email (including an existing soft-deleted user). Database constraint, serialization or deadlock conflict. Reread before retrying."
// @Failure 500 {object} httpapi.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Router /api/v1/users [post]
func (h *Handler) create(c *gin.Context) {
	var req CreateRequest
	if !httpapi.Decode(c, &req) {
		return
	}
	v, err := h.service.Create(c.Request.Context(), httpapi.Identity(c), req)
	httpapi.Reply(c, v, err, 201)
}

// list serves GET /api/v1/users.
// @Summary List current tenant users
// @Description Stable ordering by created_at then ID. Excludes soft-deleted users and removed memberships. Only documented query keys are accepted. Requires active tenant, active non-removed membership and non-deleted actor. Permission: user:read.
// @ID listUsers
// @Tags Users
// @Produce json
// @Security BearerAuth
// @x-required-permission "user:read"
// @x-identity-state-required true
// @Param page query integer false "page" minimum(1) maximum(1000000) default(1)
// @Param page_size query integer false "page_size" minimum(1) maximum(100) default(20)
// @Param q query string false "Trimmed, literal, case-insensitive substring of email/full_name; not a wildcard expression."
// @Param membership_status query string false "membership_status" Enums(active,suspended)
// @Success 200 {object} user.Page
// @Failure 400 {object} httpapi.ErrorResponse "Invalid request: JSON/content type/body size, fields, UUID, pagination, supported permission pair, or required version. Application body failures use 400, not 413/415."
// @Failure 401 {object} httpapi.ErrorResponse "Missing/invalid bearer JWT, or invalid login/refresh credentials. Authentication failures do not disclose account existence."
// @Failure 403 {object} httpapi.ErrorResponse "Valid JWT but insufficient permission, inactive tenant/membership, removed membership, deleted actor, or forbidden delegation/credential change. Authorization precedes target lookup and body validation."
// @Failure 500 {object} httpapi.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Router /api/v1/users [get]
func (h *Handler) list(c *gin.Context) {
	for key := range c.Request.URL.Query() {
		if key != "page" && key != "page_size" && key != "q" && key != "membership_status" {
			httpapi.Error(c, access.ErrInvalid)
			return
		}
	}
	page, size, err := httpapi.Pagination(c)
	if err != nil {
		httpapi.Error(c, err)
		return
	}
	v, err := h.service.List(c.Request.Context(), httpapi.Identity(c), ListQuery{page, size, c.Query("q"), c.Query("membership_status")})
	httpapi.Reply(c, v, err, 200)
}

// get serves GET /api/v1/users/{user_id}.
// @Summary Get a tenant member
// @Description Requires active tenant, active non-removed membership and non-deleted actor. Permission: user:read.
// @ID getUser
// @Tags Users
// @Produce json
// @Security BearerAuth
// @x-required-permission "user:read"
// @x-identity-state-required true
// @Param user_id path string true "user_id"
// @Success 200 {object} user.User
// @Failure 400 {object} httpapi.ErrorResponse "Invalid request: JSON/content type/body size, fields, UUID, pagination, supported permission pair, or required version. Application body failures use 400, not 413/415."
// @Failure 401 {object} httpapi.ErrorResponse "Missing/invalid bearer JWT, or invalid login/refresh credentials. Authentication failures do not disclose account existence."
// @Failure 403 {object} httpapi.ErrorResponse "Valid JWT but insufficient permission, inactive tenant/membership, removed membership, deleted actor, or forbidden delegation/credential change. Authorization precedes target lookup and body validation."
// @Failure 404 {object} httpapi.ErrorResponse "Resource is absent in the current JWT tenant, soft-deleted/removed, or the requested assignment/link is absent. Cross-tenant target resources are indistinguishable from missing resources."
// @Failure 500 {object} httpapi.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Router /api/v1/users/{user_id} [get]
func (h *Handler) get(c *gin.Context) {
	v, err := h.service.Get(c.Request.Context(), httpapi.Identity(c), c.Param("user_id"))
	httpapi.Reply(c, v, err, 200)
}

// update serves PATCH /api/v1/users/{user_id}.
// @Summary Update a tenant member profile
// @Description Set expected_updated_at to the top-level updated_at from the latest GET /api/v1/users/{user_id} response, not membership.updated_at. Copy the timestamp verbatim, preserving all fractional digits and microsecond precision; do not round to milliseconds, generate the current time, or use the Swagger example as a real version. A stale version returns 409; GET again before retrying. Shared identities with another non-removed membership return 409. Password changes revoke applicable refresh tokens and require the caller to hold the target's assigned permissions. Requires active tenant, active non-removed membership and non-deleted actor. Permission: user:update. Changes and audits commit transactionally.
// @ID updateUser
// @Tags Users
// @Produce json
// @Accept json
// @Security BearerAuth
// @x-required-permission "user:update"
// @x-identity-state-required true
// @Param user_id path string true "user_id"
// @Param request body user.UpdateRequest true "One JSON object; unknown fields/extra JSON values rejected; max 16 KiB"
// @Success 200 {object} user.User
// @Failure 400 {object} httpapi.ErrorResponse "Invalid request: JSON/content type/body size, fields, UUID, pagination, supported permission pair, or required version. Application body failures use 400, not 413/415."
// @Failure 401 {object} httpapi.ErrorResponse "Missing/invalid bearer JWT, or invalid login/refresh credentials. Authentication failures do not disclose account existence."
// @Failure 403 {object} httpapi.ErrorResponse "Valid JWT but insufficient permission, inactive tenant/membership, removed membership, deleted actor, or forbidden delegation/credential change. Authorization precedes target lookup and body validation."
// @Failure 404 {object} httpapi.ErrorResponse "Resource is absent in the current JWT tenant, soft-deleted/removed, or the requested assignment/link is absent. Cross-tenant target resources are indistinguishable from missing resources."
// @Failure 409 {object} httpapi.ErrorResponse "Stale expected_updated_at, duplicate email, or a shared identity with another non-removed tenant membership. Database constraint, serialization or deadlock conflict. Reread before retrying."
// @Failure 500 {object} httpapi.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Router /api/v1/users/{user_id} [patch]
func (h *Handler) update(c *gin.Context) {
	var req UpdateRequest
	if !httpapi.Decode(c, &req) {
		return
	}
	v, err := h.service.Update(c.Request.Context(), httpapi.Identity(c), c.Param("user_id"), req)
	httpapi.Reply(c, v, err, 200)
}

// remove serves DELETE /api/v1/users/{user_id}.
// @Summary Soft-delete a tenant user
// @Description Set expected_updated_at to the top-level updated_at from the latest GET /api/v1/users/{user_id} response, not membership.updated_at. Copy the timestamp verbatim, preserving all fractional digits and microsecond precision; do not round to milliseconds, generate the current time, or use the Swagger example as a real version. A stale version returns 409; GET again before retrying. Shared identities return 409. Retains user and membership history, marks this membership removed/suspended, and revokes refresh tokens. Does not physically delete the user. Requires active tenant, active non-removed membership and non-deleted actor. Permission: user:delete. Changes and audits commit transactionally.
// @ID deleteUser
// @Tags Users
// @Produce json
// @Accept json
// @Security BearerAuth
// @x-required-permission "user:delete"
// @x-identity-state-required true
// @Param user_id path string true "user_id"
// @Param request body user.VersionRequest true "One JSON object; unknown fields/extra JSON values rejected; max 16 KiB"
// @Success 204 "No Content; soft deletion succeeded; empty response body"
// @Failure 400 {object} httpapi.ErrorResponse "Invalid request: JSON/content type/body size, fields, UUID, pagination, supported permission pair, or required version. Application body failures use 400, not 413/415."
// @Failure 401 {object} httpapi.ErrorResponse "Missing/invalid bearer JWT, or invalid login/refresh credentials. Authentication failures do not disclose account existence."
// @Failure 403 {object} httpapi.ErrorResponse "Valid JWT but insufficient permission, inactive tenant/membership, removed membership, deleted actor, or forbidden delegation/credential change. Authorization precedes target lookup and body validation."
// @Failure 404 {object} httpapi.ErrorResponse "Resource is absent in the current JWT tenant, soft-deleted/removed, or the requested assignment/link is absent. Cross-tenant target resources are indistinguishable from missing resources."
// @Failure 409 {object} httpapi.ErrorResponse "Stale expected_updated_at or a shared identity with another non-removed tenant membership (including suspended memberships). Database constraint, serialization or deadlock conflict. Reread before retrying."
// @Failure 500 {object} httpapi.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Router /api/v1/users/{user_id} [delete]
func (h *Handler) remove(c *gin.Context) {
	var req VersionRequest
	if !httpapi.Decode(c, &req) {
		return
	}
	err := h.service.SoftDelete(c.Request.Context(), httpapi.Identity(c), c.Param("user_id"), req)
	httpapi.Reply(c, nil, err, 204)
}

// addMembership serves POST /api/v1/memberships.
// @Summary Attach an existing identity
// @Description An existing live membership conflicts. Reattaching a removed membership with historical role assignments conflicts instead of restoring old privileges. Old refresh credentials never revive. Requires active tenant, active non-removed membership and non-deleted actor. Permission: membership:create. Changes and audits commit transactionally.
// @ID addMembership
// @Tags Memberships
// @Produce json
// @Accept json
// @Security BearerAuth
// @x-required-permission "membership:create"
// @x-identity-state-required true
// @Param request body user.MembershipRequest true "One JSON object; unknown fields/extra JSON values rejected; max 16 KiB"
// @Success 201 {object} user.Membership
// @Failure 400 {object} httpapi.ErrorResponse "Invalid request: JSON/content type/body size, fields, UUID, pagination, supported permission pair, or required version. Application body failures use 400, not 413/415."
// @Failure 401 {object} httpapi.ErrorResponse "Missing/invalid bearer JWT, or invalid login/refresh credentials. Authentication failures do not disclose account existence."
// @Failure 403 {object} httpapi.ErrorResponse "Valid JWT but insufficient permission, inactive tenant/membership, removed membership, deleted actor, or forbidden delegation/credential change. Authorization precedes target lookup and body validation."
// @Failure 404 {object} httpapi.ErrorResponse "Resource is absent in the current JWT tenant, soft-deleted/removed, or the requested assignment/link is absent. Cross-tenant target resources are indistinguishable from missing resources."
// @Failure 409 {object} httpapi.ErrorResponse "Existing non-removed membership, or historical role assignments preventing reattachment of a removed membership. Database constraint, serialization or deadlock conflict. Reread before retrying."
// @Failure 500 {object} httpapi.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Router /api/v1/memberships [post]
func (h *Handler) addMembership(c *gin.Context) {
	var req MembershipRequest
	if !httpapi.Decode(c, &req) {
		return
	}
	v, err := h.service.AddMembership(c.Request.Context(), httpapi.Identity(c), req)
	httpapi.Reply(c, v, err, 201)
}

// status serves PATCH /api/v1/memberships/{user_id}.
// @Summary Change membership status
// @Description Set expected_updated_at to membership.updated_at from the latest GET /api/v1/users/{user_id} response. Copy the timestamp verbatim, preserving all fractional digits and microsecond precision; do not round to milliseconds, generate the current time, or use the Swagger example as a real version. A stale version returns 409; GET again before retrying. Requires active tenant, active non-removed membership and non-deleted actor. Permission: membership:update. Changes and audits commit transactionally.
// @ID setMembershipStatus
// @Tags Memberships
// @Produce json
// @Accept json
// @Security BearerAuth
// @x-required-permission "membership:update"
// @x-identity-state-required true
// @Param user_id path string true "user_id"
// @Param request body user.MembershipStatusRequest true "One JSON object; unknown fields/extra JSON values rejected; max 16 KiB"
// @Success 200 {object} user.Membership
// @Failure 400 {object} httpapi.ErrorResponse "Invalid request: JSON/content type/body size, fields, UUID, pagination, supported permission pair, or required version. Application body failures use 400, not 413/415."
// @Failure 401 {object} httpapi.ErrorResponse "Missing/invalid bearer JWT, or invalid login/refresh credentials. Authentication failures do not disclose account existence."
// @Failure 403 {object} httpapi.ErrorResponse "Valid JWT but insufficient permission, inactive tenant/membership, removed membership, deleted actor, or forbidden delegation/credential change. Authorization precedes target lookup and body validation."
// @Failure 404 {object} httpapi.ErrorResponse "Resource is absent in the current JWT tenant, soft-deleted/removed, or the requested assignment/link is absent. Cross-tenant target resources are indistinguishable from missing resources."
// @Failure 409 {object} httpapi.ErrorResponse "Stale membership expected_updated_at. Database constraint, serialization or deadlock conflict. Reread before retrying."
// @Failure 500 {object} httpapi.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Router /api/v1/memberships/{user_id} [patch]
func (h *Handler) status(c *gin.Context) {
	var req MembershipStatusRequest
	if !httpapi.Decode(c, &req) {
		return
	}
	v, err := h.service.SetMembershipStatus(c.Request.Context(), httpapi.Identity(c), c.Param("user_id"), req)
	httpapi.Reply(c, v, err, 200)
}

// removeMembership serves DELETE /api/v1/memberships/{user_id}.
// @Summary Logically remove a membership
// @Description Set expected_updated_at to membership.updated_at from the latest GET /api/v1/users/{user_id} response. Copy the timestamp verbatim, preserving all fractional digits and microsecond precision; do not round to milliseconds, generate the current time, or use the Swagger example as a real version. A stale version returns 409; GET again before retrying. Retains the membership, role history and refresh-token records; sets removed_at and suspended status, and revokes tenant/user refresh tokens. Requires active tenant, active non-removed membership and non-deleted actor. Permission: membership:delete. Changes and audits commit transactionally.
// @ID removeMembership
// @Tags Memberships
// @Produce json
// @Accept json
// @Security BearerAuth
// @x-required-permission "membership:delete"
// @x-identity-state-required true
// @Param user_id path string true "user_id"
// @Param request body user.VersionRequest true "One JSON object; unknown fields/extra JSON values rejected; max 16 KiB"
// @Success 204 "No content"
// @Failure 400 {object} httpapi.ErrorResponse "Invalid request: JSON/content type/body size, fields, UUID, pagination, supported permission pair, or required version. Application body failures use 400, not 413/415."
// @Failure 401 {object} httpapi.ErrorResponse "Missing/invalid bearer JWT, or invalid login/refresh credentials. Authentication failures do not disclose account existence."
// @Failure 403 {object} httpapi.ErrorResponse "Valid JWT but insufficient permission, inactive tenant/membership, removed membership, deleted actor, or forbidden delegation/credential change. Authorization precedes target lookup and body validation."
// @Failure 404 {object} httpapi.ErrorResponse "Resource is absent in the current JWT tenant, soft-deleted/removed, or the requested assignment/link is absent. Cross-tenant target resources are indistinguishable from missing resources."
// @Failure 409 {object} httpapi.ErrorResponse "Stale membership expected_updated_at. Database constraint, serialization or deadlock conflict. Reread before retrying."
// @Failure 500 {object} httpapi.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Router /api/v1/memberships/{user_id} [delete]
func (h *Handler) removeMembership(c *gin.Context) {
	var req VersionRequest
	if !httpapi.Decode(c, &req) {
		return
	}
	err := h.service.RemoveMembership(c.Request.Context(), httpapi.Identity(c), c.Param("user_id"), req)
	httpapi.Reply(c, nil, err, 204)
}
