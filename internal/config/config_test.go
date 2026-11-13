package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("JWT_SECRET", strings.Repeat("s", 32))
	t.Setenv("DATABASE_URL", "postgres://app:example@localhost/multitenant")
	t.Setenv("HTTP_ADDR", "127.0.0.1:8081")
	t.Setenv("DB_MAX_CONNS", "12")
	t.Setenv("DB_TIMEOUT", "2s")
	t.Setenv("SHUTDOWN_TIMEOUT", "8s")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPAddr != "127.0.0.1:8081" || cfg.DBMaxConns != 12 || cfg.DBTimeout != 2*time.Second || cfg.ShutdownTimeout != 8*time.Second {
		t.Fatalf("environment settings were not applied")
	}
}

func TestLoadRejectsInvalidSettings(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, tc := range []struct{ key, value string }{
		{"DATABASE_URL", ""},
		{"HTTP_ADDR", "invalid"},
		{"DB_MAX_CONNS", "0"},
		{"DB_MAX_CONNS", "2147483648"},
		{"DB_TIMEOUT", "-1s"},
		{"DB_TIMEOUT", "invalid"},
		{"SHUTDOWN_TIMEOUT", "0s"},
		{"JWT_SECRET", "short"},
		{"JWT_SECRET", strings.Repeat(" ", 32)},
		{"JWT_SECRET", "REPLACE_WITH_A_RANDOM_SECRET_OF_32_BYTES"},
		{"JWT_ISSUER", ""},
		{"ACCESS_TOKEN_TTL", "2h"},
		{"ACCESS_TOKEN_TTL", "100ms"},
		{"ACCESS_TOKEN_TTL", "0s"},
		{"REFRESH_TOKEN_TTL", "1m"},
	} {
		t.Run(tc.key+"/"+tc.value, func(t *testing.T) {
			t.Setenv("DATABASE_URL", "postgres://app:example@localhost/multitenant")
			t.Setenv("HTTP_ADDR", ":8080")
			t.Setenv("DB_MAX_CONNS", "10")
			t.Setenv("DB_TIMEOUT", "5s")
			t.Setenv("SHUTDOWN_TIMEOUT", "10s")
			t.Setenv("JWT_SECRET", strings.Repeat("s", 32))
			t.Setenv("JWT_ISSUER", "test")
			t.Setenv("ACCESS_TOKEN_TTL", "15m")
			t.Setenv("REFRESH_TOKEN_TTL", "168h")
			t.Setenv(tc.key, tc.value)
			if _, err := Load(); err == nil {
				t.Fatal("expected invalid configuration to fail")
			}
		})
	}
}

func cleanEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{"DATABASE_URL", "HTTP_ADDR", "DB_MAX_CONNS", "DB_TIMEOUT", "SHUTDOWN_TIMEOUT", "JWT_SECRET", "JWT_ISSUER", "ACCESS_TOKEN_TTL", "REFRESH_TOKEN_TTL", "APP_ENV", "SWAGGER_ENABLED"} {
		// Setenv registers cleanup restoring the original value after the test,
		// including any value subsequently loaded by godotenv.
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("JWT_SECRET", strings.Repeat("s", 32))
}

func TestSwaggerEnvironmentDefaultsAndOverrides(t *testing.T) {
	for _, tc := range []struct {
		name, environment, override string
		enabled, wantError          bool
	}{
		{"unset fails closed", "", "", false, false},
		{"development on", "development", "", true, false},
		{"production off", "production", "", false, false},
		{"staging off", "staging", "", false, false},
		{"test off", "test", "", false, false},
		{"explicit production opt in", "production", "true", true, false},
		{"development opt out", "development", "false", false, false},
		{"invalid environment", "typo", "", false, true},
		{"invalid override", "development", "not-a-bool", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			cleanEnvironment(t)
			t.Setenv("DATABASE_URL", "postgres://app:example@localhost/multitenant")
			if tc.environment != "" {
				t.Setenv("APP_ENV", tc.environment)
			}
			if tc.override != "" {
				t.Setenv("SWAGGER_ENABLED", tc.override)
			}
			cfg, err := Load()
			if tc.wantError {
				if err == nil {
					t.Fatal("invalid Swagger configuration accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.SwaggerEnabled != tc.enabled {
				t.Fatalf("SwaggerEnabled=%v want %v", cfg.SwaggerEnabled, tc.enabled)
			}
		})
	}
}

func TestLoadOptionalDotEnv(t *testing.T) {
	t.Chdir(t.TempDir())
	cleanEnvironment(t)
	contents := "DATABASE_URL=postgres://app:example@localhost/multitenant\nHTTP_ADDR=127.0.0.1:8090\nDB_MAX_CONNS=15\nDB_TIMEOUT=3s\nSHUTDOWN_TIMEOUT=9s\n"
	if err := os.WriteFile(".env", []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DatabaseURL != "postgres://app:example@localhost/multitenant" || cfg.HTTPAddr != "127.0.0.1:8090" || cfg.DBMaxConns != 15 || cfg.DBTimeout != 3*time.Second || cfg.ShutdownTimeout != 9*time.Second {
		t.Fatal(".env settings were not applied")
	}
}

func TestLoadMissingDotEnv(t *testing.T) {
	t.Chdir(t.TempDir())
	cleanEnvironment(t)
	t.Setenv("DATABASE_URL", "postgres://app:example@localhost/multitenant")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPAddr != ":8080" || cfg.DBMaxConns != 10 || cfg.DBTimeout != 5*time.Second || cfg.ShutdownTimeout != 10*time.Second || cfg.JWTIssuer != "multitenant-user-management" || cfg.AccessTokenTTL != 15*time.Minute || cfg.RefreshTokenTTL != 168*time.Hour {
		t.Fatal("defaults were not preserved without .env")
	}
}

func TestDotEnvPreservesExistingEnvironment(t *testing.T) {
	for _, existing := range []string{"postgres://existing/db", ""} {
		t.Run(existing, func(t *testing.T) {
			t.Chdir(t.TempDir())
			cleanEnvironment(t)
			t.Setenv("DATABASE_URL", existing)
			if err := os.WriteFile(".env", []byte("DATABASE_URL=postgres://file/db\n"), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load()
			if os.Getenv("DATABASE_URL") != existing {
				t.Fatal("existing environment was overwritten")
			}
			if existing == "" {
				if err == nil || err.Error() != "DATABASE_URL is required" {
					t.Fatalf("expected required-variable error, got %v", err)
				}
			} else if err != nil || cfg.DatabaseURL != existing {
				t.Fatalf("existing configuration was not preserved: %v", err)
			}
		})
	}
}

func TestLoadRejectsInvalidDotEnv(t *testing.T) {
	for _, directory := range []bool{false, true} {
		t.Run(map[bool]string{false: "malformed", true: "unreadable"}[directory], func(t *testing.T) {
			t.Chdir(t.TempDir())
			cleanEnvironment(t)
			t.Setenv("DATABASE_URL", "postgres://existing/db")
			if directory {
				if err := os.Mkdir(".env", 0700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(".env", []byte("DATABASE_URL=\"secret"), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), "could not load .env") || strings.Contains(err.Error(), "secret") {
				t.Fatalf("expected sanitized .env error, got %v", err)
			}
		})
	}
}
