package tenant

import "time"

// Tenant is the Tenant DTO.
// @Description Wire model for Tenant.
type Tenant struct {
	ID        string    `json:"id" binding:"required" format:"uuid"`
	Name      string    `json:"name" binding:"required"`
	Code      string    `json:"code" binding:"required"`
	Status    string    `json:"status" binding:"required" enums:"active,suspended"`
	CreatedAt time.Time `json:"created_at" binding:"required" format:"date-time"`
	UpdatedAt time.Time `json:"updated_at" binding:"required" format:"date-time"`
}

// CreateRequest is the internal/operator model.
// @Description Internal or operator-only CreateRequest; not an additional HTTP endpoint.
type CreateRequest struct {
	Name string `json:"name"`
	Code string `json:"code"`
}

// UpdateRequest is the TenantUpdateRequest DTO.
// @Description Set expected_updated_at to the top-level updated_at from the latest GET /api/v1/tenant. Preserve microsecond precision; example timestamps are illustrative only.
type UpdateRequest struct {
	// Trimmed, nonblank Unicode text; NUL is rejected.
	Name string `json:"name" binding:"required" minLength:"1" maxLength:"200"`
	// Copy the latest resource timestamp verbatim, preserving all fractional digits and microsecond precision. Never round to milliseconds or use this illustrative example as a real version. Stale versions return 409.
	ExpectedUpdatedAt time.Time `json:"expected_updated_at" binding:"required" format:"date-time" example:"2026-01-02T03:04:05.123456Z"`
}

// StatusRequest is the TenantStatusRequest DTO.
// @Description Set expected_updated_at to the top-level updated_at from the latest GET /api/v1/tenant. Preserve microsecond precision; example timestamps are illustrative only.
type StatusRequest struct {
	Status string `json:"status" binding:"required" enums:"active,suspended"`
	// Copy the latest resource timestamp verbatim, preserving all fractional digits and microsecond precision. Never round to milliseconds or use this illustrative example as a real version. Stale versions return 409.
	ExpectedUpdatedAt time.Time `json:"expected_updated_at" binding:"required" format:"date-time" example:"2026-01-02T03:04:05.123456Z"`
}
