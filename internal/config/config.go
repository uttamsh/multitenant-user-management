package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// Config contains settings loaded from the process environment.
type Config struct {
	AppEnv          string
	SwaggerEnabled  bool
	HTTPAddr        string
	DatabaseURL     string
	DBMaxConns      int32
	DBTimeout       time.Duration
	ShutdownTimeout time.Duration
	JWTSecret       string
	JWTIssuer       string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
}

// Load reads an optional .env file from the working directory, then validates
// configuration. Existing environment variables, including empty ones, win.
func Load() (Config, error) {
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		// Parser errors can contain file contents, including credentials.
		return Config{}, errors.New("could not load .env: check file access and syntax")
	}
	c := Config{
		AppEnv:      strings.ToLower(strings.TrimSpace(value("APP_ENV", "production"))),
		HTTPAddr:    value("HTTP_ADDR", ":8080"),
		DatabaseURL: strings.TrimSpace(os.Getenv("DATABASE_URL")),
		JWTSecret:   os.Getenv("JWT_SECRET"),
		JWTIssuer:   value("JWT_ISSUER", "multitenant-user-management"),
	}
	switch c.AppEnv {
	case "development", "test", "staging", "production":
	default:
		return Config{}, fmt.Errorf("APP_ENV must be development, test, staging or production")
	}
	enabled, err := strconv.ParseBool(value("SWAGGER_ENABLED", strconv.FormatBool(c.AppEnv == "development")))
	if err != nil {
		return Config{}, fmt.Errorf("SWAGGER_ENABLED must be a boolean")
	}
	c.SwaggerEnabled = enabled
	if _, _, err := net.SplitHostPort(c.HTTPAddr); err != nil {
		return Config{}, fmt.Errorf("HTTP_ADDR must be a host:port address")
	}
	if c.DatabaseURL == "" {
		return Config{}, fmt.Errorf("DATABASE_URL is required")
	}
	n, err := strconv.ParseInt(value("DB_MAX_CONNS", "10"), 10, 32)
	if err != nil || n <= 0 {
		return Config{}, fmt.Errorf("DB_MAX_CONNS must be a positive 32-bit integer")
	}
	c.DBMaxConns = int32(n)
	if c.DBTimeout, err = duration("DB_TIMEOUT", "5s"); err != nil {
		return Config{}, err
	}
	if c.ShutdownTimeout, err = duration("SHUTDOWN_TIMEOUT", "10s"); err != nil {
		return Config{}, err
	}
	if len(strings.TrimSpace(c.JWTSecret)) < 32 || strings.Contains(strings.ToUpper(c.JWTSecret), "REPLACE") {
		return Config{}, fmt.Errorf("JWT_SECRET must contain at least 32 bytes and must not be a placeholder")
	}
	if strings.TrimSpace(c.JWTIssuer) == "" {
		return Config{}, fmt.Errorf("JWT_ISSUER must not be empty")
	}
	if c.AccessTokenTTL, err = duration("ACCESS_TOKEN_TTL", "15m"); err != nil {
		return Config{}, err
	}
	if c.RefreshTokenTTL, err = duration("REFRESH_TOKEN_TTL", "168h"); err != nil {
		return Config{}, err
	}
	if c.AccessTokenTTL < time.Second || c.AccessTokenTTL > time.Hour || c.RefreshTokenTTL <= c.AccessTokenTTL {
		return Config{}, fmt.Errorf("ACCESS_TOKEN_TTL must be between 1s and 1h; REFRESH_TOKEN_TTL must be longer")
	}
	return c, nil
}

func value(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

func duration(key, fallback string) (time.Duration, error) {
	d, err := time.ParseDuration(value(key, fallback))
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration such as 5s", key)
	}
	return d, nil
}
