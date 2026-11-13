package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/uttam/multitenant-user-management/internal/auth"
	"github.com/uttam/multitenant-user-management/internal/config"
	"github.com/uttam/multitenant-user-management/internal/database"
	"github.com/uttam/multitenant-user-management/internal/rbac"
	"github.com/uttam/multitenant-user-management/internal/server"
	"github.com/uttam/multitenant-user-management/internal/tenant"
	"github.com/uttam/multitenant-user-management/internal/user"
)

// @title Multi-Tenant User Management API
// @version 1.0.0
// @description Source-backed documentation for 30 application operations. Protected operations require Authorize with Bearer <access JWT>. Tenant identity comes only from validated JWT context; client headers, query parameters and request bodies cannot select the authorization tenant. Permissions are evaluated within that tenant; cross-tenant target lookups return 404 after authorization. No public registration, HTTP tenant bootstrap or audit-log query endpoint exists. Management changes and audits commit together; login audits are best effort. Body errors use 400, not 413/415. Database failures normally use sanitized 500; readiness uses 503. Router fallbacks use JSON 404/405. Swagger documentation routes are excluded from this inventory.
// @BasePath /
// @x-supported-permissions ["tenant:read", "tenant:update", "tenant:status", "user:create", "user:read", "user:update", "user:delete", "membership:create", "membership:update", "membership:delete", "role:create", "role:read", "role:update", "role:delete", "role_permission:assign", "role_permission:remove", "user_role:assign", "user_role:remove", "permission:read", "user_permission:read"]
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Click Authorize and enter Bearer <access JWT>, including the Bearer prefix and space. The validated JWT selects the tenant; client-supplied tenant IDs are never trusted. Roles/permissions are checked in PostgreSQL, not trusted from JWT claims. Never enter a refresh token here.
func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, logger); err != nil {
		logger.Error("application stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	tokens, err := auth.NewTokens(cfg.JWTSecret, cfg.JWTIssuer, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
	if err != nil {
		return err
	}
	pool, err := database.Open(ctx, cfg.DatabaseURL, cfg.DBMaxConns, cfg.DBTimeout)
	if err != nil {
		return err
	}
	defer pool.Close()
	service, err := auth.NewService(auth.NewRepository(pool), tokens, logger)
	if err != nil {
		return err
	}
	handler := auth.NewHandler(service, cfg.DBTimeout, logger)
	policy := rbac.NewPolicy(pool)
	tenantHandler := tenant.NewHandler(tenant.NewService(tenant.NewRepository(pool), policy), tokens, cfg.DBTimeout)
	userHandler := user.NewHandler(user.NewService(user.NewRepository(pool), policy), tokens, cfg.DBTimeout)
	rbacHandler := rbac.NewHandler(rbac.NewService(rbac.NewRepository(pool), policy), tokens, cfg.DBTimeout)
	gin.SetMode(gin.ReleaseMode)
	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           server.NewRouter(pool, cfg.DBTimeout, logger, handler, tenantHandler, userHandler, rbacHandler, server.NewSwagger(cfg.SwaggerEnabled)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      cfg.DBTimeout + 10*time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}
	serveErr := make(chan error, 1)
	go func() {
		logger.Info("starting HTTP server", "address", cfg.HTTPAddr)
		serveErr <- srv.ListenAndServe()
	}()
	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		logger.Info("shutting down HTTP server")
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		_ = srv.Close()
		return err
	}
	return nil
}
