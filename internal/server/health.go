package server

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/uttam/multitenant-user-management/internal/middleware"
)

// HealthResponse reports application liveness independently of database state.
// @Description Liveness after successful application startup.
type HealthResponse struct {
	Status string `json:"status" binding:"required" enums:"ok"`
}

// ReadyResponse reports a successful bounded database ping.
// @Description Database readiness; a failed ping returns 503 instead.
type ReadyResponse struct {
	Status string `json:"status" binding:"required" enums:"ready"`
}

type probes struct {
	db      Pinger
	timeout time.Duration
}

// health serves GET /health.
// @Summary Application liveness
// @Description Independent of database state after successful application startup.
// @ID getHealth
// @Tags Operations
// @Produce json
// @x-required-permission null
// @x-identity-state-required false
// @Success 200 {object} server.HealthResponse
// @Failure 500 {object} middleware.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Router /health [get]
func (p probes) health(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) }

// ready serves GET /ready.
// @Summary Database readiness
// @Description Bounded pool ping. Startup itself fails if the database is initially unavailable.
// @ID getReady
// @Tags Operations
// @Produce json
// @x-required-permission null
// @x-identity-state-required false
// @Success 200 {object} server.ReadyResponse
// @Failure 500 {object} middleware.ErrorResponse "Sanitized internal/database failure; no driver details or credentials returned."
// @Failure 503 {object} middleware.ErrorResponse "Readiness database ping failed or timed out."
// @Router /ready [get]
func (p probes) ready(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), p.timeout)
	defer cancel()
	if err := p.db.Ping(ctx); err != nil {
		middleware.Error(c, http.StatusServiceUnavailable, "database_unavailable", "Database is unavailable")
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ready"})
}
