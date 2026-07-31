package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/riyanathariq/tools-api.riyanathariq.space/internal/auth"
	"github.com/riyanathariq/tools-api.riyanathariq.space/internal/visitor"
)

type visitorPayload struct {
	VisitorID string `json:"visitor_id"`
	SessionID string `json:"session_id"`
	Path      string `json:"path"`
	Referer   string `json:"referer"`
	Origin    string `json:"origin"`
}

func (s *Server) handleVisitorEvent(w http.ResponseWriter, r *http.Request) {
	if ok, retry := s.limiter.Allow("visitor:"+clientIP(r), 60, time.Minute); !ok {
		w.Header().Set("Retry-After", "60")
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":         "rate limit exceeded",
			"retryAfterSec": int(retry.Seconds()) + 1,
		})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<10))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var payload visitorPayload
	if len(body) > 0 {
		if err := json.Unmarshal(body, &payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}

	if !visitor.ValidID(payload.VisitorID) || !visitor.ValidID(payload.SessionID) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	userID := ""
	if u, err := s.sessions.UserFromRequest(r); err == nil && u != nil {
		userID = u.ID
	}

	referer := strings.TrimSpace(payload.Referer)
	if referer == "" {
		referer = r.Referer()
	}
	origin := strings.TrimSpace(payload.Origin)
	if origin == "" {
		origin = r.Header.Get("Origin")
	}
	path := strings.TrimSpace(payload.Path)
	if path == "" {
		path = "/"
	}

	// Respond immediately; persist async.
	w.WriteHeader(http.StatusNoContent)

	s.visitors.TrackAsync(visitor.Record{
		VisitorID: payload.VisitorID,
		SessionID: payload.SessionID,
		IP:        clientIP(r),
		UserAgent: r.UserAgent(),
		Referer:   referer,
		Origin:    origin,
		Country:   firstNonEmpty(r.Header.Get("CF-IPCountry"), r.Header.Get("CloudFront-Viewer-Country")),
		City:      firstNonEmpty(r.Header.Get("CF-IPCity"), r.Header.Get("X-City")),
		UserID:    userID,
		FirstPath: path,
	})
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v != "" && !strings.EqualFold(v, "XX") {
			return v
		}
	}
	return ""
}

// RequireActiveUser wraps session auth with a ban check against Postgres.
func (s *Server) RequireActiveUser(next http.Handler) http.Handler {
	return s.sessions.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := auth.UserFromContext(r.Context())
		if !ok || u == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthenticated"})
			return
		}
		banned, err := s.users.IsBanned(r.Context(), u.ID)
		if err != nil {
			s.log.Error("ban check failed", "err", err, "user_id", u.ID)
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "session check failed"})
			return
		}
		if banned {
			s.sessions.Clear(w)
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "account banned"})
			return
		}
		next.ServeHTTP(w, r)
	}))
}
