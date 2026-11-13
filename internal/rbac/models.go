package rbac

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// Role is the Role DTO.
// @Description Wire model for Role.
type Role struct {
	ID          string    `json:"id" binding:"required" format:"uuid"`
	Name        string    `json:"name" binding:"required"`
	Description string    `json:"description" binding:"required"`
	CreatedAt   time.Time `json:"created_at" binding:"required" format:"date-time"`
	// Opaque profile-content digest from the role response. Not a permission-grant version.
	Version string `json:"version" binding:"required"`
}

// Version is an opaque representation digest for optimistic profile updates;
// permissions and assignments are managed separately through grant endpoints.
func (r *Role) setVersion() {
	b, _ := json.Marshal([]string{r.ID, r.Name, r.Description})
	digest := sha256.Sum256(b)
	r.Version = hex.EncodeToString(digest[:])
}

// CreateRoleRequest is the RoleCreateRequest DTO.
// @Description Wire model for RoleCreateRequest.
type CreateRoleRequest struct {
	// Trimmed, nonblank, case-sensitive; unique within the current tenant.
	Name string `json:"name" binding:"required" minLength:"1" maxLength:"100"`
	// Trimmed text. Omission on role PATCH clears the description.
	Description string `json:"description" maxLength:"2000"`
}

// UpdateRoleRequest is the RoleUpdateRequest DTO.
// @Description Replaces the role profile; omitted description becomes empty.
type UpdateRoleRequest struct {
	// Trimmed, nonblank, case-sensitive; unique within the current tenant.
	Name string `json:"name" binding:"required" minLength:"1" maxLength:"100"`
	// Trimmed text. Omission on role PATCH clears the description.
	Description string `json:"description" maxLength:"2000"`
	// Copy the exact version from the latest GET /api/v1/roles/{role_id}. This opaque profile-content digest is not a timestamp or permission-grant version; stale values return 409.
	ExpectedVersion string `json:"expected_version" binding:"required"`
}

// DeleteRoleRequest is the RoleDeleteRequest DTO.
// @Description Wire model for RoleDeleteRequest.
type DeleteRoleRequest struct {
	// Copy the exact version from the latest GET /api/v1/roles/{role_id}. This opaque profile-content digest is not a timestamp or permission-grant version; stale values return 409.
	ExpectedVersion string `json:"expected_version" binding:"required"`
}

// Permission is the Permission DTO.
// @Description Wire model for Permission.
type Permission struct {
	ID       string `json:"id,omitempty" format:"uuid"`
	Resource string `json:"resource" binding:"required"`
	Action   string `json:"action" binding:"required"`
}

func (p Permission) Key() string { return p.Resource + ":" + p.Action }

// PermissionRequest is the PermissionRequest DTO.
// @Description The pair must be one of the 20 supported catalog permissions, not merely two independently valid strings. No wildcards or custom pairs.
type PermissionRequest struct {
	Resource string `json:"resource" binding:"required" enums:"tenant,user,membership,role,role_permission,user_role,permission,user_permission"`
	Action   string `json:"action" binding:"required" enums:"read,create,update,delete,status,assign,remove"`
}

// RolePage is the RolePage DTO.
// @Description Wire model for RolePage.
type RolePage struct {
	Items    []Role `json:"items" binding:"required"`
	Page     int    `json:"page" binding:"required"`
	PageSize int    `json:"page_size" binding:"required"`
	Total    int64  `json:"total" binding:"required" format:"int64"`
}

// Catalog defines supported permissions, with no wildcard/admin-name bypass.
func Catalog() []Permission {
	var result []Permission
	for _, entry := range []struct {
		resource string
		actions  []string
	}{
		{"tenant", []string{"read", "update", "status"}},
		{"user", []string{"create", "read", "update", "delete"}},
		{"membership", []string{"create", "update", "delete"}},
		{"role", []string{"create", "read", "update", "delete"}},
		{"role_permission", []string{"assign", "remove"}},
		{"user_role", []string{"assign", "remove"}},
		{"permission", []string{"read"}},
		{"user_permission", []string{"read"}},
	} {
		for _, action := range entry.actions {
			result = append(result, Permission{Resource: entry.resource, Action: action})
		}
	}
	return result
}
func supported(resource, action string) bool {
	for _, p := range Catalog() {
		if p.Resource == resource && p.Action == action {
			return true
		}
	}
	return false
}
