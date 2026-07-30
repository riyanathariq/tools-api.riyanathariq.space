package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/riyanathariq/tools-api.riyanathariq.space/internal/auth"
	"github.com/riyanathariq/tools-api.riyanathariq.space/internal/config"
	"github.com/riyanathariq/tools-api.riyanathariq.space/internal/ratelimit"
)

type Server struct {
	cfg      config.Config
	log      *slog.Logger
	google   *auth.GoogleAuth
	sessions *auth.SessionManager
	limiter  *ratelimit.Limiter
	started  time.Time
}

func New(
	cfg config.Config,
	log *slog.Logger,
	google *auth.GoogleAuth,
	sessions *auth.SessionManager,
	limiter *ratelimit.Limiter,
) http.Handler {
	s := &Server{
		cfg:      cfg,
		log:      log,
		google:   google,
		sessions: sessions,
		limiter:  limiter,
		started:  time.Now().UTC(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)

	mux.HandleFunc("GET /auth/status", s.google.Status)
	mux.HandleFunc("GET /auth/google", s.google.Begin)
	mux.HandleFunc("GET /auth/google/callback", s.google.Callback)
	mux.HandleFunc("GET /auth/me", s.google.Me)
	mux.HandleFunc("POST /auth/logout", s.google.Logout)

	mux.Handle("POST /api/cloud/smtp/test", s.sessions.RequireUser(http.HandlerFunc(s.handleSMTPTest)))

	return chain(
		mux,
		withRecover(log),
		withAccessLog(log),
		withSecurityHeaders,
		withCORS(cfg.AllowedOrigins),
	)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"service": "tools-api",
		"uptime":  time.Since(s.started).String(),
	})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ready := true
	reasons := []string{}
	if !s.google.Enabled() && s.cfg.Env == "production" {
		ready = false
		reasons = append(reasons, "google_oauth_not_configured")
	}
	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]any{
		"ready":   ready,
		"reasons": reasons,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
