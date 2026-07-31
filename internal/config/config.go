package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr           string
	PublicBaseURL  string
	FrontendURL    string
	DatabaseURL    string
	ValkeyURL      string
	SessionSecret  string
	GoogleClientID string
	GoogleSecret   string
	CookieName     string
	CookieSecure   bool
	SessionTTL     time.Duration
	AllowedOrigins []string
	Env            string
}

func Load() (Config, error) {
	ttlHours := envInt("SESSION_TTL_HOURS", 168)
	cfg := Config{
		Addr:           env("HTTP_ADDR", ":3003"),
		PublicBaseURL:  strings.TrimRight(env("PUBLIC_BASE_URL", "http://localhost:3000"), "/"),
		FrontendURL:    strings.TrimRight(env("FRONTEND_URL", "http://localhost:3000"), "/"),
		DatabaseURL:    env("DATABASE_URL", "postgres://tools:tools@127.0.0.1:5432/tools?sslmode=disable"),
		ValkeyURL:      env("VALKEY_URL", "redis://127.0.0.1:6379/0"),
		SessionSecret:  env("SESSION_SECRET", ""),
		GoogleClientID: env("GOOGLE_CLIENT_ID", ""),
		GoogleSecret:   env("GOOGLE_CLIENT_SECRET", ""),
		CookieName:     env("SESSION_COOKIE", "tools_session"),
		CookieSecure:   envBool("COOKIE_SECURE", false),
		SessionTTL:     time.Duration(ttlHours) * time.Hour,
		AllowedOrigins: splitCSV(env("CORS_ORIGINS", "http://localhost:3000")),
		Env:            env("APP_ENV", "development"),
	}

	if cfg.SessionSecret == "" {
		if cfg.Env == "production" {
			return Config{}, fmt.Errorf("SESSION_SECRET is required in production")
		}
		cfg.SessionSecret = "dev-only-insecure-session-secret-change-me"
	}
	if len(cfg.SessionSecret) < 32 {
		return Config{}, fmt.Errorf("SESSION_SECRET must be at least 32 characters")
	}
	if cfg.SessionTTL < time.Hour {
		return Config{}, fmt.Errorf("SESSION_TTL_HOURS must be >= 1")
	}
	if strings.TrimSpace(cfg.DatabaseURL) == "" {
		return Config{}, fmt.Errorf("DATABASE_URL is required")
	}
	if strings.TrimSpace(cfg.ValkeyURL) == "" {
		return Config{}, fmt.Errorf("VALKEY_URL is required")
	}
	return cfg, nil
}

func (c Config) GoogleEnabled() bool {
	return strings.TrimSpace(c.GoogleClientID) != "" && strings.TrimSpace(c.GoogleSecret) != ""
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envBool(key string, def bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if v == "" {
		return def
	}
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
