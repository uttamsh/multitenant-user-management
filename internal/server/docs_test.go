package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/goccy/go-yaml"
	"github.com/uttam/multitenant-user-management/internal/access"
	"github.com/uttam/multitenant-user-management/internal/auth"
	"github.com/uttam/multitenant-user-management/internal/rbac"
	"github.com/uttam/multitenant-user-management/internal/tenant"
	"github.com/uttam/multitenant-user-management/internal/user"
)

type documentedSchema struct {
	Properties map[string]any `json:"properties"`
}
type documentedOperation struct {
	OperationID    string                `json:"operationId"`
	Description    string                `json:"description"`
	Security       []map[string][]string `json:"security"`
	Permission     *string               `json:"x-required-permission"`
	ActiveIdentity bool                  `json:"x-identity-state-required"`
	Responses      map[string]any        `json:"responses"`
	Parameters     []struct {
		Name     string `json:"name"`
		In       string `json:"in"`
		Required bool   `json:"required"`
	} `json:"parameters"`
}

func TestSwaggerOptimisticConcurrencyGuidance(t *testing.T) {
	doc := loadDocumentation(t)
	for _, tc := range []struct {
		path, method, source string
	}{
		{"/api/v1/users/{user_id}", "patch", "top-level updated_at"},
		{"/api/v1/users/{user_id}", "delete", "top-level updated_at"},
		{"/api/v1/memberships/{user_id}", "patch", "membership.updated_at"},
		{"/api/v1/memberships/{user_id}", "delete", "membership.updated_at"},
		{"/api/v1/tenant", "patch", "top-level updated_at"},
		{"/api/v1/tenant/status", "patch", "top-level updated_at"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			op := doc.Paths[tc.path][tc.method]
			for _, guidance := range []string{tc.source, "latest GET", "microsecond precision", "do not round to milliseconds", "409"} {
				if !strings.Contains(op.Description, guidance) {
					t.Errorf("missing concurrency guidance: %s", guidance)
				}
			}
			conflict, ok := op.Responses["409"].(map[string]any)
			if !ok || !strings.Contains(strings.ToLower(conflict["description"].(string)), "stale") {
				t.Error("missing stale-version conflict response")
			}
		})
	}
	for _, model := range []string{"user.UpdateRequest", "user.VersionRequest", "user.MembershipStatusRequest", "tenant.UpdateRequest", "tenant.StatusRequest"} {
		field := doc.Definitions[model].Properties["expected_updated_at"].(map[string]any)
		example, ok := field["example"].(string)
		parsed, err := time.Parse(time.RFC3339Nano, example)
		if !ok || err != nil || parsed.Nanosecond()%1000 != 0 || parsed.Nanosecond()%1000000 == 0 {
			t.Errorf("%s needs a realistic example preserving sub-millisecond precision", model)
		}
	}
	for _, method := range []string{"patch", "delete"} {
		op := doc.Paths["/api/v1/roles/{role_id}"][method]
		for _, guidance := range []string{"expected_version", "latest GET", "opaque profile digest, not a timestamp", "409"} {
			if !strings.Contains(op.Description, guidance) {
				t.Errorf("role %s missing guidance: %s", method, guidance)
			}
		}
	}
	deletion := doc.Paths["/api/v1/users/{user_id}"]["delete"]
	response, ok := deletion.Responses["204"].(map[string]any)
	if !ok || response["schema"] != nil || !strings.Contains(response["description"].(string), "No Content") {
		t.Error("user deletion must document 204 No Content without a response body schema")
	}
	for _, guidance := range []string{"Does not physically delete", "Retains user and membership history", "Shared identities return 409"} {
		if !strings.Contains(deletion.Description, guidance) {
			t.Errorf("missing soft-deletion guidance: %s", guidance)
		}
	}
	for _, tc := range []struct{ path, method, condition string }{
		{"/api/v1/users", "post", "Duplicate email"},
		{"/api/v1/users/{user_id}", "patch", "shared identity"},
		{"/api/v1/users/{user_id}", "delete", "shared identity"},
		{"/api/v1/memberships", "post", "historical role assignments"},
		{"/api/v1/roles", "post", "Duplicate role name"},
		{"/api/v1/roles/{role_id}", "patch", "duplicate role name"},
		{"/api/v1/roles/{role_id}/permissions", "post", "Duplicate role-permission link"},
		{"/api/v1/users/{user_id}/roles/{role_id}", "put", "Duplicate user-role assignment"},
	} {
		response := doc.Paths[tc.path][tc.method].Responses["409"].(map[string]any)
		if !strings.Contains(response["description"].(string), tc.condition) {
			t.Errorf("%s %s missing conflict condition: %s", tc.method, tc.path, tc.condition)
		}
	}
}

func TestSwaggerArtifactsAndReferences(t *testing.T) {
	dir := filepath.Join("..", "..", "docs", "swagger")
	jsonData, err := os.ReadFile(filepath.Join(dir, "swagger.json"))
	if err != nil {
		t.Fatal(err)
	}
	yamlData, err := os.ReadFile(filepath.Join(dir, "swagger.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	converted, err := yaml.YAMLToJSON(yamlData)
	if err != nil {
		t.Fatal(err)
	}
	var spec, yamlSpec map[string]any
	if err := json.Unmarshal(jsonData, &spec); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(converted, &yamlSpec); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(spec, yamlSpec) {
		t.Fatal("generated JSON and YAML differ")
	}
	if spec["swagger"] != "2.0" {
		t.Fatal("unexpected specification version")
	}
	definitions := spec["definitions"].(map[string]any)
	var check func(any)
	check = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			if ref, ok := value["$ref"].(string); ok {
				if !strings.HasPrefix(ref, "#/definitions/") || definitions[strings.TrimPrefix(ref, "#/definitions/")] == nil {
					t.Errorf("unresolved reference: %s", ref)
				}
			}
			for key, child := range value {
				if key == "password_hash" || key == "token_hash" {
					t.Errorf("internal secret field exposed: %s", key)
				}
				check(child)
			}
		case []any:
			for _, child := range value {
				check(child)
			}
		}
	}
	check(spec)
	parameter := regexp.MustCompile(`\{([^}]+)\}`)
	for path, methods := range loadDocumentation(t).Paths {
		for method, operation := range methods {
			want := map[string]bool{}
			for _, match := range parameter.FindAllStringSubmatch(path, -1) {
				want[match[1]] = true
			}
			for _, p := range operation.Parameters {
				if p.In != "path" {
					continue
				}
				if !want[p.Name] || !p.Required {
					t.Errorf("invalid path parameter %s: %s %s", p.Name, method, path)
				}
				delete(want, p.Name)
			}
			if len(want) != 0 {
				t.Errorf("missing path parameters: %s %s", method, path)
			}
		}
	}
}

func TestSwaggerPermissionsMatchRegisteredChecks(t *testing.T) {
	doc := loadDocumentation(t)
	group := regexp.MustCompile(`g\s*:=\s*r\.Group\("([^"]*)"`)
	route := regexp.MustCompile(`(?m)^\s*[rg]\.(GET|POST|PUT|PATCH|DELETE)\("([^"]*)"([^\n]*)`)
	require := regexp.MustCompile(`httpapi\.Require\([^,]+,\s*"([^"]+)"`)
	pathParameter := regexp.MustCompile(`:([A-Za-z_][A-Za-z0-9_]*)`)
	count := 0
	for _, file := range []string{"server/router.go", "auth/handler.go", "tenant/handler.go", "user/handler.go", "rbac/handler.go"} {
		data, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(file)))
		if err != nil {
			t.Fatal(err)
		}
		prefix := ""
		if m := group.FindStringSubmatch(string(data)); m != nil {
			prefix = m[1]
		}
		for _, m := range route.FindAllStringSubmatch(string(data), -1) {
			path := pathParameter.ReplaceAllString(prefix+m[2], "{$1}")
			method := strings.ToLower(m[1])
			operation, ok := doc.Paths[path][method]
			if !ok {
				t.Fatalf("source operation missing: %s %s", method, path)
			}
			permission := ""
			if r := require.FindStringSubmatch(m[3]); r != nil {
				permission = r[1]
			}
			if operation.ActiveIdentity != (permission != "") {
				t.Errorf("incorrect active identity requirement: %s %s", method, path)
			}
			if permission == "" || permission == "identity.active" {
				if operation.Permission != nil {
					t.Errorf("invented permission: %s %s", method, path)
				}
			} else if operation.Permission == nil || *operation.Permission != strings.Replace(permission, ".", ":", 1) {
				t.Errorf("permission differs from handler: %s %s", method, path)
			}
			if _, ok := operation.Responses["500"]; !ok {
				t.Errorf("missing internal error response: %s %s", method, path)
			}
			if permission != "" {
				for _, status := range []string{"401", "403"} {
					if _, ok := operation.Responses[status]; !ok {
						t.Errorf("missing %s response: %s %s", status, method, path)
					}
				}
			}
			count++
		}
	}
	if count != 30 {
		t.Fatalf("checked %d application operations, expected 30", count)
	}
}

type documentation struct {
	Paths       map[string]map[string]documentedOperation `json:"paths"`
	Permissions []string                                  `json:"x-supported-permissions"`
	Definitions map[string]documentedSchema               `json:"definitions"`
}

func loadDocumentation(t *testing.T) documentation {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "swagger", "swagger.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc documentation
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// Construct the same registrars as cmd/api without opening a database, starting
// a server, issuing tokens, running bootstrap, or invoking any handler.
func TestSwaggerMatchesGinRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	tokens, err := auth.NewTokens(strings.Repeat("documentation-test-key", 2), "documentation", time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	policy := access.DenyAll{}
	r := NewRouter(nil, time.Second, logger, auth.NewHandler(nil, time.Second, logger), tenant.NewHandler(tenant.NewService(nil, policy), tokens, time.Second), user.NewHandler(user.NewService(nil, policy), tokens, time.Second), rbac.NewHandler(rbac.NewService(nil, policy), tokens, time.Second), NewSwagger(true))
	doc := loadDocumentation(t)
	actual := map[string]bool{}
	pathParameter := regexp.MustCompile(`:([A-Za-z_][A-Za-z0-9_]*)`)
	for _, route := range r.Routes() {
		if strings.HasPrefix(route.Path, "/swagger/") {
			continue
		}
		actual[strings.ToLower(route.Method)+" "+pathParameter.ReplaceAllString(route.Path, "{$1}")] = true
	}
	documented := map[string]bool{}
	ids := map[string]bool{}
	for path, item := range doc.Paths {
		for method, operation := range item {
			key := method + " " + path
			documented[key] = true
			if !actual[key] {
				t.Errorf("documented operation is not registered: %s", key)
			}
			if operation.OperationID == "" || ids[operation.OperationID] {
				t.Errorf("missing/duplicate operationId: %s", key)
			}
			ids[operation.OperationID] = true
			public := path == "/health" || path == "/ready" || strings.HasPrefix(path, "/api/v1/auth/")
			if public && len(operation.Security) != 0 {
				t.Errorf("public operation requires bearer security: %s", key)
			}
			if !public {
				if len(operation.Security) != 1 {
					t.Errorf("protected operation missing bearer security: %s", key)
				} else if _, ok := operation.Security[0]["BearerAuth"]; !ok {
					t.Errorf("wrong security scheme: %s", key)
				}
			}
		}
	}
	for key := range actual {
		if !documented[key] {
			t.Errorf("registered operation is undocumented: %s", key)
		}
	}
	t.Logf("matched %d Gin operations across %d documented paths", len(actual), len(doc.Paths))
	var permissions []string
	for _, p := range rbac.Catalog() {
		permissions = append(permissions, p.Key())
	}
	sort.Strings(permissions)
	sort.Strings(doc.Permissions)
	if !reflect.DeepEqual(permissions, doc.Permissions) {
		t.Error("Swagger permission catalog differs from production catalog")
	}
}

func TestSwaggerMatchesDTOFields(t *testing.T) {
	doc := loadDocumentation(t)
	models := map[string]any{
		"auth.LoginRequest": auth.LoginRequest{}, "auth.RefreshRequest": auth.RefreshRequest{}, "auth.TokenPair": auth.TokenPair{},
		"tenant.Tenant": tenant.Tenant{}, "tenant.UpdateRequest": tenant.UpdateRequest{}, "tenant.StatusRequest": tenant.StatusRequest{},
		"user.User": user.User{}, "user.Membership": user.Membership{}, "user.CreateRequest": user.CreateRequest{}, "user.UpdateRequest": user.UpdateRequest{}, "user.VersionRequest": user.VersionRequest{}, "user.MembershipRequest": user.MembershipRequest{}, "user.MembershipStatusRequest": user.MembershipStatusRequest{}, "user.Page": user.Page{},
		"rbac.Role": rbac.Role{}, "rbac.CreateRoleRequest": rbac.CreateRoleRequest{}, "rbac.UpdateRoleRequest": rbac.UpdateRoleRequest{}, "rbac.DeleteRoleRequest": rbac.DeleteRoleRequest{}, "rbac.Permission": rbac.Permission{}, "rbac.PermissionRequest": rbac.PermissionRequest{}, "rbac.RolePage": rbac.RolePage{},
		"server.HealthResponse": HealthResponse{}, "server.ReadyResponse": ReadyResponse{},
	}
	for name, value := range models {
		t.Run(name, func(t *testing.T) {
			schema, ok := doc.Definitions[name]
			if !ok {
				t.Fatal("schema missing")
			}
			typ := reflect.TypeOf(value)
			fields := map[string]bool{}
			for i := 0; i < typ.NumField(); i++ {
				tag := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
				if tag != "" && tag != "-" {
					fields[tag] = true
				}
			}
			if len(fields) != len(schema.Properties) {
				t.Errorf("schema has %d properties; DTO has %d", len(schema.Properties), len(fields))
			}
			for field := range fields {
				if _, ok := schema.Properties[field]; !ok {
					t.Errorf("DTO field missing from schema: %s", field)
				}
			}
			for field := range schema.Properties {
				if !fields[field] {
					t.Errorf("invented schema field: %s", field)
				}
			}
		})
	}
}
