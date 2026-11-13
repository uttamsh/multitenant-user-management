package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/uttam/multitenant-user-management/internal/middleware"
)

type Pinger interface {
	Ping(context.Context) error
}

type Registrar interface{ Register(*gin.Engine) }

// NewRouter exposes probes and, when supplied, the authentication handler.
// Business routes require authentication and tenant-aware authorization.
func NewRouter(db Pinger, timeout time.Duration, logger *slog.Logger, handlers ...Registrar) *gin.Engine {
	r := gin.New()
	// No forwarding proxy is trusted until explicitly configured.
	_ = r.SetTrustedProxies(nil)
	r.HandleMethodNotAllowed = true
	r.Use(middleware.RequestLogger(logger), middleware.Recovery(logger))
	for _, handler := range handlers {
		handler.Register(r)
	}
	p := probes{db: db, timeout: timeout}
	r.GET("/health", p.health)
	r.GET("/ready", p.ready)
	r.NoRoute(func(c *gin.Context) {
		middleware.Error(c, http.StatusNotFound, "not_found", "Route not found")
	})
	r.NoMethod(func(c *gin.Context) {
		middleware.Error(c, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
	})
	return r
}
