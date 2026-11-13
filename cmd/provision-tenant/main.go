// provision-tenant is an explicit administrative operation, never an HTTP route.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/uttam/multitenant-user-management/internal/access"
	"github.com/uttam/multitenant-user-management/internal/config"
	"github.com/uttam/multitenant-user-management/internal/database"
	"github.com/uttam/multitenant-user-management/internal/rbac"
	"github.com/uttam/multitenant-user-management/internal/tenant"
)

func main() {
	admin := flag.Bool("administrative", false, "explicitly authorize administrative tenant provisioning")
	name := flag.String("name", "", "tenant name")
	code := flag.String("code", "", "unique lowercase tenant code")
	bootstrap := flag.Bool("bootstrap-admin", false, "explicitly approve INITIAL administrator grant")
	existing := flag.Bool("existing", false, "bootstrap an existing tenant instead of creating one")
	adminUserID := flag.String("admin-user-id", "", "existing user UUID selected by the operator")
	flag.Parse()
	if !*admin || flag.NArg() != 0 || strings.TrimSpace(*code) == "" || (!*existing && strings.TrimSpace(*name) == "") || (!*bootstrap && (*existing || *adminUserID != "")) || (*bootstrap && *adminUserID == "") || (*existing && *name != "") {
		fmt.Fprintln(os.Stderr, "refusing to provision: use --administrative and --code with --name for a new tenant; bootstrap additionally requires --bootstrap-admin and --admin-user-id (use --existing without --name for an existing tenant)")
		os.Exit(1)
	}
	if err := run(*name, *code, *bootstrap, *existing, *adminUserID); err != nil {
		fmt.Fprintln(os.Stderr, "tenant provisioning failed: verify configuration, input and unique tenant code; no partial changes committed")
		os.Exit(1)
	}
}
func run(name, code string, bootstrap, existing bool, adminUserID string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, cfg.DatabaseURL, cfg.DBMaxConns, cfg.DBTimeout)
	if err != nil {
		return err
	}
	defer pool.Close()
	if bootstrap {
		result, err := rbac.Bootstrap(ctx, pool, rbac.BootstrapRequest{Approved: true, ExistingTenant: existing, Name: name, Code: code, AdminUserID: adminUserID})
		if err != nil {
			return err
		}
		fmt.Printf("Initialized administrator for tenant %s; user %s\n", result.TenantID, result.AdminUserID)
		return nil
	}
	service := tenant.NewService(tenant.NewRepository(pool), access.DenyAll{})
	t, err := service.Provision(ctx, tenant.CreateRequest{Name: name, Code: code})
	if err != nil {
		return err
	}
	fmt.Printf("Provisioned tenant %s (%s)\n", t.ID, t.Code)
	return nil
}
