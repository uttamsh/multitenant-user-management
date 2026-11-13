package middleware

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// ErrorResponse is the common application error envelope.
// @Description Sanitized application error; raw driver/panic/credential details are omitted.
type ErrorResponse struct {
	Error ErrorDetail `json:"error" binding:"required"`
}

// ErrorDetail identifies an application failure without sensitive details.
// @Description Stable code and a human-readable message; authorization precedes target lookup.
type ErrorDetail struct {
	Code    string `json:"code" binding:"required" example:"invalid_request"`
	Message string `json:"message" binding:"required" example:"Invalid request"`
}

// Error aborts the handler chain with the API's common error envelope.
func Error(c *gin.Context, status int, code, message string) {
	c.AbortWithStatusJSON(status, ErrorResponse{Error: ErrorDetail{Code: code, Message: message}})
}

func RequestLogger(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		logger.Info("http request",
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"duration", time.Since(start),
		)
	}
}

func Recovery(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if recover() != nil {
				// Panic values may include secrets; do not serialize them.
				logger.Error("request panic recovered", "method", c.Request.Method, "path", c.Request.URL.Path)
				if !c.Writer.Written() {
					Error(c, http.StatusInternalServerError, "internal_error", "An internal error occurred")
				} else {
					c.Abort()
				}
			}
		}()
		c.Next()
	}
}
