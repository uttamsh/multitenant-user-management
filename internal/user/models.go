package user

import "time"

// Membership is the Membership DTO.
// @Description Wire model for Membership.
type Membership struct {
	UserID    string    `json:"user_id" binding:"required" format:"uuid"`
	Status    string    `json:"status" binding:"required" enums:"active,suspended"`
	JoinedAt  time.Time `json:"joined_at" binding:"required" format:"date-time"`
	UpdatedAt time.Time `json:"updated_at" binding:"required" format:"date-time"`
}

// User is the User DTO.
// @Description Wire model for User.
type User struct {
	ID string `json:"id" binding:"required" format:"uuid"`
	// Trimmed bare email address. PostgreSQL LOWER supplies case normalization for stored values.
	Email      string     `json:"email" binding:"required" format:"email" minLength:"1" maxLength:"255"`
	FullName   string     `json:"full_name" binding:"required"`
	CreatedAt  time.Time  `json:"created_at" binding:"required" format:"date-time"`
	UpdatedAt  time.Time  `json:"updated_at" binding:"required" format:"date-time"`
	Membership Membership `json:"membership" binding:"required"`
}

// CreateRequest is the UserCreateRequest DTO.
// @Description Wire model for UserCreateRequest.
type CreateRequest struct {
	// Trimmed bare email address. PostgreSQL LOWER supplies case normalization for stored values.
	Email string `json:"email" binding:"required" format:"email" minLength:"1" maxLength:"255"`
	// Trimmed, nonblank Unicode text; NUL is rejected.
	FullName string `json:"full_name" binding:"required" minLength:"1" maxLength:"200"`
	// 12–72 UTF-8 bytes, not Unicode characters. bcrypt-hashed; never returned.
	Password string `json:"password" binding:"required" format:"password" extensions:"x-min-bytes=12,x-max-bytes=72"`
}

// UpdateRequest is the UserUpdateRequest DTO.
// @Description Copy expected_updated_at from the top-level updated_at of the latest GET /api/v1/users/{user_id}, not membership.updated_at. Preserve microsecond precision. At least one non-null change is required. Explicit null pointers act as omitted fields. Shared identities cannot be edited by tenant APIs (409). Password changes additionally require the caller to hold the target's assigned permissions.
type UpdateRequest struct {
	// Trimmed bare email address. PostgreSQL LOWER supplies case normalization for stored values.
	Email *string `json:"email,omitempty" format:"email" minLength:"1" maxLength:"255" extensions:"x-nullable"`
	// Trimmed, nonblank Unicode text; NUL is rejected.
	FullName *string `json:"full_name,omitempty" minLength:"1" maxLength:"200" extensions:"x-nullable"`
	// 12–72 UTF-8 bytes, not Unicode characters. bcrypt-hashed; never returned.
	Password *string `json:"password,omitempty" format:"password" extensions:"x-min-bytes=12,x-max-bytes=72,x-nullable"`
	// Copy the latest resource timestamp verbatim, preserving all fractional digits and microsecond precision. Never round to milliseconds or use this illustrative example as a real version. Stale versions return 409.
	ExpectedUpdatedAt time.Time `json:"expected_updated_at" binding:"required" format:"date-time" example:"2026-01-02T03:04:05.123456Z"`
}

// VersionRequest is the VersionRequest DTO.
// @Description For user deletion copy the top-level updated_at from the latest GET /api/v1/users/{user_id}; do not use membership.updated_at. For membership removal copy membership.updated_at from that GET response. Preserve microsecond precision; example timestamps are illustrative only.
type VersionRequest struct {
	// Copy the latest resource timestamp verbatim, preserving all fractional digits and microsecond precision. Never round to milliseconds or use this illustrative example as a real version. Stale versions return 409.
	ExpectedUpdatedAt time.Time `json:"expected_updated_at" binding:"required" format:"date-time" example:"2026-01-02T03:04:05.123456Z"`
}

// MembershipRequest is the MembershipCreateRequest DTO.
// @Description Attach a known non-deleted identity to the JWT tenant; no global user search or implicit email attachment.
type MembershipRequest struct {
	UserID string `json:"user_id" binding:"required" format:"uuid"`
}

// MembershipStatusRequest is the MembershipStatusRequest DTO.
// @Description Set expected_updated_at to membership.updated_at from the latest GET /api/v1/users/{user_id}; preserve microsecond precision. Activation requires the caller to hold all target assigned permissions, including dormant grants. Removed memberships cannot be changed through this route.
type MembershipStatusRequest struct {
	Status string `json:"status" binding:"required" enums:"active,suspended"`
	// Copy the latest resource timestamp verbatim, preserving all fractional digits and microsecond precision. Never round to milliseconds or use this illustrative example as a real version. Stale versions return 409.
	ExpectedUpdatedAt time.Time `json:"expected_updated_at" binding:"required" format:"date-time" example:"2026-01-02T03:04:05.123456Z"`
}

// ListQuery is the internal/operator model.
// @Description Internal or operator-only ListQuery; not an additional HTTP endpoint.
type ListQuery struct {
	Page             int
	PageSize         int
	Search           string
	MembershipStatus string
}

// Page is the UserPage DTO.
// @Description Wire model for UserPage.
type Page struct {
	Items    []User `json:"items" binding:"required"`
	Page     int    `json:"page" binding:"required"`
	PageSize int    `json:"page_size" binding:"required"`
	Total    int64  `json:"total" binding:"required" format:"int64"`
}
