package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSwaggerUIAndEmbeddedSpecExposure(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	for _, enabled := range []bool{false, true} {
		router := NewRouter(nil, time.Second, logger, NewSwagger(enabled))
		for _, path := range []string{"/swagger/index.html", "/swagger/doc.json", "/swagger/swagger-initializer.js", "/swagger/swagger-ui-bundle.js", "/swagger/swagger-ui.css"} {
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
			want := 404
			if enabled {
				want = 200
			}
			if w.Code != want {
				t.Fatalf("enabled=%v %s HTTP %d want %d", enabled, path, w.Code, want)
			}
			if !enabled {
				continue
			}
			switch path {
			case "/swagger/index.html":
				if !strings.Contains(w.Body.String(), "swagger-ui") || !strings.Contains(w.Body.String(), "swagger-initializer.js") {
					t.Fatal("Swagger UI HTML missing initialization")
				}
			case "/swagger/swagger-initializer.js":
				if !strings.Contains(w.Body.String(), "persistAuthorization: false") || !strings.Contains(w.Body.String(), `url: "doc.json"`) || !strings.Contains(w.Body.String(), "validatorUrl: null") {
					t.Fatal("Swagger UI persistence/same-origin configuration incorrect")
				}
			case "/swagger/doc.json":
				var doc struct {
					Swagger             string                                     `json:"swagger"`
					Paths               map[string]any                             `json:"paths"`
					SecurityDefinitions map[string]struct{ Type, In, Name string } `json:"securityDefinitions"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
					t.Fatal(err)
				}
				if doc.Swagger != "2.0" || len(doc.Paths) != 19 {
					t.Fatal("embedded Swagger spec incomplete")
				}
				security := doc.SecurityDefinitions["BearerAuth"]
				if security.Type != "apiKey" || security.In != "header" || security.Name != "Authorization" {
					t.Fatal("Authorize button scheme does not send Authorization header")
				}
				data, err := os.ReadFile(filepath.Join("..", "..", "docs", "swagger", "swagger.json"))
				if err != nil {
					t.Fatal(err)
				}
				var fileSpec, embeddedSpec map[string]any
				if err := json.Unmarshal(data, &fileSpec); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(w.Body.Bytes(), &embeddedSpec); err != nil {
					t.Fatal(err)
				}
				for _, field := range []string{"paths", "definitions", "securityDefinitions", "x-supported-permissions"} {
					if !reflect.DeepEqual(fileSpec[field], embeddedSpec[field]) {
						t.Errorf("embedded spec differs from generated JSON for %s", field)
					}
				}
			}
		}
	}
}
