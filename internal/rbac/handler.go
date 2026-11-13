package rbac

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
	g.POST("/roles", httpapi.Require(h.service.policy, "role.create"), h.create)
	g.GET("/roles", httpapi.Require(h.service.policy, "role.read"), h.list)
	g.GET("/roles/:role_id", httpapi.Require(h.service.policy, "role.read"), h.get)
	g.PATCH("/roles/:role_id", httpapi.Require(h.service.policy, "role.update"), h.update)
	g.DELETE("/roles/:role_id", httpapi.Require(h.service.policy, "role.delete"), h.remove)
	g.GET("/permissions", httpapi.Require(h.service.policy, "permission.read"), h.catalog)
	g.GET("/roles/:role_id/permissions", httpapi.Require(h.service.policy, "role.read"), h.rolePermissions)
	g.POST("/roles/:role_id/permissions", httpapi.Require(h.service.policy, "role_permission.assign"), h.assignPermission)
	g.DELETE("/roles/:role_id/permissions", httpapi.Require(h.service.policy, "role_permission.remove"), h.removePermission)
	g.GET("/users/:user_id/roles", httpapi.Require(h.service.policy, "user_permission.read"), h.userRoles)
	g.PUT("/users/:user_id/roles/:role_id", httpapi.Require(h.service.policy, "user_role.assign"), h.assignRole)
	g.DELETE("/users/:user_id/roles/:role_id", httpapi.Require(h.service.policy, "user_role.remove"), h.removeRole)
	g.GET("/users/:user_id/permissions", httpapi.Require(h.service.policy, "user_permission.read"), h.effective)
	g.GET("/me/permissions", httpapi.Require(h.service.policy, "identity.active"), h.self)
}

// create serves POST /api/v1/roles.
// @Summary Create a tenant role
// @Description Requires active tenant, active non-removed membership and non-deleted actor. Permission: role:create. Changes and audits commit transactionally.
// @ID createRole
// @Tags RBAC
// @Produce json
// @Accept json
// @Security BearerAuth
// @x-required-permission "role:create"
// @x-identity-state-required true
// @Param request body rbac.CreateRoleRequest true "One JSON object; unknown fields/extra JSON values rejected; max 16 KiB"
// @Success 201 {object} rbac.Role
// @Failure 400 {object} httpapi.ErrorResponse "Invalid request: JSON/content type/body size, fields, UUID, pagination, supported permission pair, or required version. Application body failures use 400, not 413/415."
// @Failure 401 {object} httpapi.ErrorResponse "Missing/invalid bearer JWT, or invalid login/refresh credentials. Authentication failures do not disclose account existence."
// @Failure 403 {object} httpapi.ErrorResponse "Valid JWT but insufficient permission, inactive tenant/membership, removed membership, deleted actor, or forbidden delegation/credential change. Authorization precedes target lookup and body validation."
// @Failure 409 {object} httpapi.ErrorResponse "Duplicate role name within the tenant. Database constraint, serialization or deadlock conflict. Reread before retrying."
// @Failure 500 {object} httpapi.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Router /api/v1/roles [post]
func (h *Handler) create(c *gin.Context) {
	var req CreateRoleRequest
	if !httpapi.Decode(c, &req) {
		return
	}
	v, err := h.service.CreateRole(c.Request.Context(), httpapi.Identity(c), req)
	httpapi.Reply(c, v, err, 201)
}

// list serves GET /api/v1/roles.
// @Summary List current tenant roles
// @Description Only page and page_size query keys are accepted. Ordered by created_at then ID. Requires active tenant, active non-removed membership and non-deleted actor. Permission: role:read.
// @ID listRoles
// @Tags RBAC
// @Produce json
// @Security BearerAuth
// @x-required-permission "role:read"
// @x-identity-state-required true
// @Param page query integer false "page" minimum(1) maximum(1000000) default(1)
// @Param page_size query integer false "page_size" minimum(1) maximum(100) default(20)
// @Success 200 {object} rbac.RolePage
// @Failure 400 {object} httpapi.ErrorResponse "Invalid request: JSON/content type/body size, fields, UUID, pagination, supported permission pair, or required version. Application body failures use 400, not 413/415."
// @Failure 401 {object} httpapi.ErrorResponse "Missing/invalid bearer JWT, or invalid login/refresh credentials. Authentication failures do not disclose account existence."
// @Failure 403 {object} httpapi.ErrorResponse "Valid JWT but insufficient permission, inactive tenant/membership, removed membership, deleted actor, or forbidden delegation/credential change. Authorization precedes target lookup and body validation."
// @Failure 500 {object} httpapi.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Router /api/v1/roles [get]
func (h *Handler) list(c *gin.Context) {
	for key := range c.Request.URL.Query() {
		if key != "page" && key != "page_size" {
			httpapi.Error(c, access.ErrInvalid)
			return
		}
	}
	page, size, err := httpapi.Pagination(c)
	if err != nil {
		httpapi.Error(c, err)
		return
	}
	v, err := h.service.ListRoles(c.Request.Context(), httpapi.Identity(c), page, size)
	httpapi.Reply(c, v, err, 200)
}

// get serves GET /api/v1/roles/{role_id}.
// @Summary Get a tenant role
// @Description Requires active tenant, active non-removed membership and non-deleted actor. Permission: role:read.
// @ID getRole
// @Tags RBAC
// @Produce json
// @Security BearerAuth
// @x-required-permission "role:read"
// @x-identity-state-required true
// @Param role_id path string true "role_id"
// @Success 200 {object} rbac.Role
// @Failure 400 {object} httpapi.ErrorResponse "Invalid request: JSON/content type/body size, fields, UUID, pagination, supported permission pair, or required version. Application body failures use 400, not 413/415."
// @Failure 401 {object} httpapi.ErrorResponse "Missing/invalid bearer JWT, or invalid login/refresh credentials. Authentication failures do not disclose account existence."
// @Failure 403 {object} httpapi.ErrorResponse "Valid JWT but insufficient permission, inactive tenant/membership, removed membership, deleted actor, or forbidden delegation/credential change. Authorization precedes target lookup and body validation."
// @Failure 404 {object} httpapi.ErrorResponse "Resource is absent in the current JWT tenant, soft-deleted/removed, or the requested assignment/link is absent. Cross-tenant target resources are indistinguishable from missing resources."
// @Failure 500 {object} httpapi.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Router /api/v1/roles/{role_id} [get]
func (h *Handler) get(c *gin.Context) {
	v, err := h.service.GetRole(c.Request.Context(), httpapi.Identity(c), c.Param("role_id"))
	httpapi.Reply(c, v, err, 200)
}

// update serves PATCH /api/v1/roles/{role_id}.
// @Summary Replace a role profile
// @Description Set expected_version to the exact version from the latest GET /api/v1/roles/{role_id} response; this is an opaque profile digest, not a timestamp. A stale version returns 409; GET again before retrying. Requires active tenant, active non-removed membership and non-deleted actor. Permission: role:update. Changes and audits commit transactionally.
// @ID updateRole
// @Tags RBAC
// @Produce json
// @Accept json
// @Security BearerAuth
// @x-required-permission "role:update"
// @x-identity-state-required true
// @Param role_id path string true "role_id"
// @Param request body rbac.UpdateRoleRequest true "One JSON object; unknown fields/extra JSON values rejected; max 16 KiB"
// @Success 200 {object} rbac.Role
// @Failure 400 {object} httpapi.ErrorResponse "Invalid request: JSON/content type/body size, fields, UUID, pagination, supported permission pair, or required version. Application body failures use 400, not 413/415."
// @Failure 401 {object} httpapi.ErrorResponse "Missing/invalid bearer JWT, or invalid login/refresh credentials. Authentication failures do not disclose account existence."
// @Failure 403 {object} httpapi.ErrorResponse "Valid JWT but insufficient permission, inactive tenant/membership, removed membership, deleted actor, or forbidden delegation/credential change. Authorization precedes target lookup and body validation."
// @Failure 404 {object} httpapi.ErrorResponse "Resource is absent in the current JWT tenant, soft-deleted/removed, or the requested assignment/link is absent. Cross-tenant target resources are indistinguishable from missing resources."
// @Failure 409 {object} httpapi.ErrorResponse "Stale expected_version or duplicate role name within the tenant. Database constraint, serialization or deadlock conflict. Reread before retrying."
// @Failure 500 {object} httpapi.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Router /api/v1/roles/{role_id} [patch]
func (h *Handler) update(c *gin.Context) {
	var req UpdateRoleRequest
	if !httpapi.Decode(c, &req) {
		return
	}
	v, err := h.service.UpdateRole(c.Request.Context(), httpapi.Identity(c), c.Param("role_id"), req)
	httpapi.Reply(c, v, err, 200)
}

// remove serves DELETE /api/v1/roles/{role_id}.
// @Summary Delete a role and its grant links
// @Description Set expected_version to the exact version from the latest GET /api/v1/roles/{role_id} response; this is an opaque profile digest, not a timestamp. A stale version returns 409; GET again before retrying. Transactionally removes only this tenant role's permission links and user assignments, auditing each removal. Global permission identifiers and unrelated roles remain. Requires active tenant, active non-removed membership and non-deleted actor. Permission: role:delete. Changes and audits commit transactionally.
// @ID deleteRole
// @Tags RBAC
// @Produce json
// @Accept json
// @Security BearerAuth
// @x-required-permission "role:delete"
// @x-identity-state-required true
// @Param role_id path string true "role_id"
// @Param request body rbac.DeleteRoleRequest true "One JSON object; unknown fields/extra JSON values rejected; max 16 KiB"
// @Success 204 "No content"
// @Failure 400 {object} httpapi.ErrorResponse "Invalid request: JSON/content type/body size, fields, UUID, pagination, supported permission pair, or required version. Application body failures use 400, not 413/415."
// @Failure 401 {object} httpapi.ErrorResponse "Missing/invalid bearer JWT, or invalid login/refresh credentials. Authentication failures do not disclose account existence."
// @Failure 403 {object} httpapi.ErrorResponse "Valid JWT but insufficient permission, inactive tenant/membership, removed membership, deleted actor, or forbidden delegation/credential change. Authorization precedes target lookup and body validation."
// @Failure 404 {object} httpapi.ErrorResponse "Resource is absent in the current JWT tenant, soft-deleted/removed, or the requested assignment/link is absent. Cross-tenant target resources are indistinguishable from missing resources."
// @Failure 409 {object} httpapi.ErrorResponse "Stale expected_version. Database constraint, serialization or deadlock conflict. Reread before retrying."
// @Failure 500 {object} httpapi.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Router /api/v1/roles/{role_id} [delete]
func (h *Handler) remove(c *gin.Context) {
	var req DeleteRoleRequest
	if !httpapi.Decode(c, &req) {
		return
	}
	err := h.service.DeleteRole(c.Request.Context(), httpapi.Identity(c), c.Param("role_id"), req)
	httpapi.Reply(c, nil, err, 204)
}

// catalog serves GET /api/v1/permissions.
// @Summary Read the persisted permission catalog
// @Description Global identifiers, not global authority. Historical unsupported entries may be present; only supported pairs authorize actions. Requires active tenant, active non-removed membership and non-deleted actor. Permission: permission:read.
// @ID listPermissions
// @Tags RBAC
// @Produce json
// @Security BearerAuth
// @x-required-permission "permission:read"
// @x-identity-state-required true
// @Success 200 {array} rbac.Permission
// @Failure 401 {object} httpapi.ErrorResponse "Missing/invalid bearer JWT, or invalid login/refresh credentials. Authentication failures do not disclose account existence."
// @Failure 403 {object} httpapi.ErrorResponse "Valid JWT but insufficient permission, inactive tenant/membership, removed membership, deleted actor, or forbidden delegation/credential change. Authorization precedes target lookup and body validation."
// @Failure 500 {object} httpapi.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Router /api/v1/permissions [get]
func (h *Handler) catalog(c *gin.Context) {
	v, err := h.service.Catalog(c.Request.Context(), httpapi.Identity(c))
	httpapi.Reply(c, v, err, 200)
}

// rolePermissions serves GET /api/v1/roles/{role_id}/permissions.
// @Summary List role permission links
// @Description Requires active tenant, active non-removed membership and non-deleted actor. Permission: role:read.
// @ID listRolePermissions
// @Tags RBAC
// @Produce json
// @Security BearerAuth
// @x-required-permission "role:read"
// @x-identity-state-required true
// @Param role_id path string true "role_id"
// @Success 200 {array} rbac.Permission
// @Failure 400 {object} httpapi.ErrorResponse "Invalid request: JSON/content type/body size, fields, UUID, pagination, supported permission pair, or required version. Application body failures use 400, not 413/415."
// @Failure 401 {object} httpapi.ErrorResponse "Missing/invalid bearer JWT, or invalid login/refresh credentials. Authentication failures do not disclose account existence."
// @Failure 403 {object} httpapi.ErrorResponse "Valid JWT but insufficient permission, inactive tenant/membership, removed membership, deleted actor, or forbidden delegation/credential change. Authorization precedes target lookup and body validation."
// @Failure 404 {object} httpapi.ErrorResponse "Resource is absent in the current JWT tenant, soft-deleted/removed, or the requested assignment/link is absent. Cross-tenant target resources are indistinguishable from missing resources."
// @Failure 500 {object} httpapi.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Router /api/v1/roles/{role_id}/permissions [get]
func (h *Handler) rolePermissions(c *gin.Context) {
	v, err := h.service.RolePermissions(c.Request.Context(), httpapi.Identity(c), c.Param("role_id"))
	httpapi.Reply(c, v, err, 200)
}

// assignPermission serves POST /api/v1/roles/{role_id}/permissions.
// @Summary Grant a permission to a role
// @Description Caller must also currently hold the permission being granted; cannot delegate beyond their authority. Requires active tenant, active non-removed membership and non-deleted actor. Permission: role_permission:assign. Changes and audits commit transactionally.
// @ID assignPermission
// @Tags RBAC
// @Produce json
// @Accept json
// @Security BearerAuth
// @x-required-permission "role_permission:assign"
// @x-identity-state-required true
// @Param role_id path string true "role_id"
// @Param request body rbac.PermissionRequest true "One JSON object; unknown fields/extra JSON values rejected; max 16 KiB"
// @Success 204 "No content"
// @Failure 400 {object} httpapi.ErrorResponse "Invalid request: JSON/content type/body size, fields, UUID, pagination, supported permission pair, or required version. Application body failures use 400, not 413/415."
// @Failure 401 {object} httpapi.ErrorResponse "Missing/invalid bearer JWT, or invalid login/refresh credentials. Authentication failures do not disclose account existence."
// @Failure 403 {object} httpapi.ErrorResponse "Valid JWT but insufficient permission, inactive tenant/membership, removed membership, deleted actor, or forbidden delegation/credential change. Authorization precedes target lookup and body validation."
// @Failure 404 {object} httpapi.ErrorResponse "Resource is absent in the current JWT tenant, soft-deleted/removed, or the requested assignment/link is absent. Cross-tenant target resources are indistinguishable from missing resources."
// @Failure 409 {object} httpapi.ErrorResponse "Duplicate role-permission link. Database constraint, serialization or deadlock conflict. Reread before retrying."
// @Failure 500 {object} httpapi.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Router /api/v1/roles/{role_id}/permissions [post]
func (h *Handler) assignPermission(c *gin.Context) { h.changePermission(c, true) }

// removePermission serves DELETE /api/v1/roles/{role_id}/permissions.
// @Summary Remove a role permission
// @Description Requires active tenant, active non-removed membership and non-deleted actor. Permission: role_permission:remove. Changes and audits commit transactionally.
// @ID revokePermission
// @Tags RBAC
// @Produce json
// @Accept json
// @Security BearerAuth
// @x-required-permission "role_permission:remove"
// @x-identity-state-required true
// @Param role_id path string true "role_id"
// @Param request body rbac.PermissionRequest true "One JSON object; unknown fields/extra JSON values rejected; max 16 KiB"
// @Success 204 "No content"
// @Failure 400 {object} httpapi.ErrorResponse "Invalid request: JSON/content type/body size, fields, UUID, pagination, supported permission pair, or required version. Application body failures use 400, not 413/415."
// @Failure 401 {object} httpapi.ErrorResponse "Missing/invalid bearer JWT, or invalid login/refresh credentials. Authentication failures do not disclose account existence."
// @Failure 403 {object} httpapi.ErrorResponse "Valid JWT but insufficient permission, inactive tenant/membership, removed membership, deleted actor, or forbidden delegation/credential change. Authorization precedes target lookup and body validation."
// @Failure 404 {object} httpapi.ErrorResponse "Resource is absent in the current JWT tenant, soft-deleted/removed, or the requested assignment/link is absent. Cross-tenant target resources are indistinguishable from missing resources."
// @Failure 409 {object} httpapi.ErrorResponse "Database constraint, serialization or deadlock conflict. Reread before retrying."
// @Failure 500 {object} httpapi.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Router /api/v1/roles/{role_id}/permissions [delete]
func (h *Handler) removePermission(c *gin.Context) { h.changePermission(c, false) }
func (h *Handler) changePermission(c *gin.Context, assign bool) {
	var req PermissionRequest
	if !httpapi.Decode(c, &req) {
		return
	}
	err := h.service.ChangePermission(c.Request.Context(), httpapi.Identity(c), c.Param("role_id"), req, assign)
	httpapi.Reply(c, nil, err, 204)
}

// userRoles serves GET /api/v1/users/{user_id}/roles.
// @Summary List a tenant member's assigned roles
// @Description May include suspended members' dormant assignments; removed memberships and deleted users are not targetable. Requires active tenant, active non-removed membership and non-deleted actor. Permission: user_permission:read.
// @ID listUserRoles
// @Tags RBAC
// @Produce json
// @Security BearerAuth
// @x-required-permission "user_permission:read"
// @x-identity-state-required true
// @Param user_id path string true "user_id"
// @Success 200 {array} rbac.Role
// @Failure 400 {object} httpapi.ErrorResponse "Invalid request: JSON/content type/body size, fields, UUID, pagination, supported permission pair, or required version. Application body failures use 400, not 413/415."
// @Failure 401 {object} httpapi.ErrorResponse "Missing/invalid bearer JWT, or invalid login/refresh credentials. Authentication failures do not disclose account existence."
// @Failure 403 {object} httpapi.ErrorResponse "Valid JWT but insufficient permission, inactive tenant/membership, removed membership, deleted actor, or forbidden delegation/credential change. Authorization precedes target lookup and body validation."
// @Failure 404 {object} httpapi.ErrorResponse "Resource is absent in the current JWT tenant, soft-deleted/removed, or the requested assignment/link is absent. Cross-tenant target resources are indistinguishable from missing resources."
// @Failure 500 {object} httpapi.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Router /api/v1/users/{user_id}/roles [get]
func (h *Handler) userRoles(c *gin.Context) {
	v, err := h.service.UserRoles(c.Request.Context(), httpapi.Identity(c), c.Param("user_id"))
	httpapi.Reply(c, v, err, 200)
}

// assignRole serves PUT /api/v1/users/{user_id}/roles/{role_id}.
// @Summary Assign a tenant role
// @Description No body. Duplicate assignment returns 409. Caller must hold every supported permission already granted by that role. Requires active tenant, active non-removed membership and non-deleted actor. Permission: user_role:assign. Changes and audits commit transactionally.
// @ID assignUserRole
// @Tags RBAC
// @Produce json
// @Security BearerAuth
// @x-required-permission "user_role:assign"
// @x-identity-state-required true
// @Param user_id path string true "user_id"
// @Param role_id path string true "role_id"
// @Success 204 "No content"
// @Failure 400 {object} httpapi.ErrorResponse "Invalid request: JSON/content type/body size, fields, UUID, pagination, supported permission pair, or required version. Application body failures use 400, not 413/415."
// @Failure 401 {object} httpapi.ErrorResponse "Missing/invalid bearer JWT, or invalid login/refresh credentials. Authentication failures do not disclose account existence."
// @Failure 403 {object} httpapi.ErrorResponse "Valid JWT but insufficient permission, inactive tenant/membership, removed membership, deleted actor, or forbidden delegation/credential change. Authorization precedes target lookup and body validation."
// @Failure 404 {object} httpapi.ErrorResponse "Resource is absent in the current JWT tenant, soft-deleted/removed, or the requested assignment/link is absent. Cross-tenant target resources are indistinguishable from missing resources."
// @Failure 409 {object} httpapi.ErrorResponse "Duplicate user-role assignment. Database constraint, serialization or deadlock conflict. Reread before retrying."
// @Failure 500 {object} httpapi.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Router /api/v1/users/{user_id}/roles/{role_id} [put]
func (h *Handler) assignRole(c *gin.Context) { h.changeRole(c, true) }

// removeRole serves DELETE /api/v1/users/{user_id}/roles/{role_id}.
// @Summary Remove a user role assignment
// @Description Requires active tenant, active non-removed membership and non-deleted actor. Permission: user_role:remove. Changes and audits commit transactionally.
// @ID revokeUserRole
// @Tags RBAC
// @Produce json
// @Security BearerAuth
// @x-required-permission "user_role:remove"
// @x-identity-state-required true
// @Param user_id path string true "user_id"
// @Param role_id path string true "role_id"
// @Success 204 "No content"
// @Failure 400 {object} httpapi.ErrorResponse "Invalid request: JSON/content type/body size, fields, UUID, pagination, supported permission pair, or required version. Application body failures use 400, not 413/415."
// @Failure 401 {object} httpapi.ErrorResponse "Missing/invalid bearer JWT, or invalid login/refresh credentials. Authentication failures do not disclose account existence."
// @Failure 403 {object} httpapi.ErrorResponse "Valid JWT but insufficient permission, inactive tenant/membership, removed membership, deleted actor, or forbidden delegation/credential change. Authorization precedes target lookup and body validation."
// @Failure 404 {object} httpapi.ErrorResponse "Resource is absent in the current JWT tenant, soft-deleted/removed, or the requested assignment/link is absent. Cross-tenant target resources are indistinguishable from missing resources."
// @Failure 409 {object} httpapi.ErrorResponse "Database constraint, serialization or deadlock conflict. Reread before retrying."
// @Failure 500 {object} httpapi.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Router /api/v1/users/{user_id}/roles/{role_id} [delete]
func (h *Handler) removeRole(c *gin.Context) { h.changeRole(c, false) }
func (h *Handler) changeRole(c *gin.Context, assign bool) {
	err := h.service.ChangeUserRole(c.Request.Context(), httpapi.Identity(c), c.Param("user_id"), c.Param("role_id"), assign)
	httpapi.Reply(c, nil, err, 204)
}

// effective serves GET /api/v1/users/{user_id}/permissions.
// @Summary List effective tenant permission union
// @Description Distinct union of supported permissions across roles; suspended target memberships have an empty set. Requires active tenant, active non-removed membership and non-deleted actor. Permission: user_permission:read.
// @ID listEffectivePermissions
// @Tags RBAC
// @Produce json
// @Security BearerAuth
// @x-required-permission "user_permission:read"
// @x-identity-state-required true
// @Param user_id path string true "user_id"
// @Success 200 {array} rbac.Permission
// @Failure 400 {object} httpapi.ErrorResponse "Invalid request: JSON/content type/body size, fields, UUID, pagination, supported permission pair, or required version. Application body failures use 400, not 413/415."
// @Failure 401 {object} httpapi.ErrorResponse "Missing/invalid bearer JWT, or invalid login/refresh credentials. Authentication failures do not disclose account existence."
// @Failure 403 {object} httpapi.ErrorResponse "Valid JWT but insufficient permission, inactive tenant/membership, removed membership, deleted actor, or forbidden delegation/credential change. Authorization precedes target lookup and body validation."
// @Failure 404 {object} httpapi.ErrorResponse "Resource is absent in the current JWT tenant, soft-deleted/removed, or the requested assignment/link is absent. Cross-tenant target resources are indistinguishable from missing resources."
// @Failure 500 {object} httpapi.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Router /api/v1/users/{user_id}/permissions [get]
func (h *Handler) effective(c *gin.Context) {
	v, err := h.service.Effective(c.Request.Context(), httpapi.Identity(c), c.Param("user_id"), false)
	httpapi.Reply(c, v, err, 200)
}

// self serves GET /api/v1/me/permissions.
// @Summary List caller's effective permission union
// @Description Any active authenticated member may inspect their own permissions; no catalog grant is required. Inactive identities return 403, and ordinary members usually receive an empty array. Requires active tenant, active non-removed membership and non-deleted actor. No catalog grant required for own permissions.
// @ID listMyPermissions
// @Tags RBAC
// @Produce json
// @Security BearerAuth
// @x-required-permission null
// @x-identity-state-required true
// @Success 200 {array} rbac.Permission
// @Failure 401 {object} httpapi.ErrorResponse "Missing/invalid bearer JWT, or invalid login/refresh credentials. Authentication failures do not disclose account existence."
// @Failure 403 {object} httpapi.ErrorResponse "Valid JWT but insufficient permission, inactive tenant/membership, removed membership, deleted actor, or forbidden delegation/credential change. Authorization precedes target lookup and body validation."
// @Failure 500 {object} httpapi.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Router /api/v1/me/permissions [get]
func (h *Handler) self(c *gin.Context) {
	v, err := h.service.Effective(c.Request.Context(), httpapi.Identity(c), "", true)
	httpapi.Reply(c, v, err, 200)
}
