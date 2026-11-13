package server

import (
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	_ "github.com/uttam/multitenant-user-management/docs/swagger"
)

type swaggerRegistrar struct{ enabled bool }

// NewSwagger registers documentation only when configuration explicitly enables
// it. The wildcard covers HTML, local assets and the embedded JSON specification.
// Application endpoints retain their existing authentication and RBAC checks.
func NewSwagger(enabled bool) Registrar { return swaggerRegistrar{enabled: enabled} }

func (s swaggerRegistrar) Register(r *gin.Engine) {
	if !s.enabled {
		return
	}
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler,
		ginSwagger.URL("doc.json"), ginSwagger.PersistAuthorization(false),
		ginSwagger.DocExpansion("none")))
}
