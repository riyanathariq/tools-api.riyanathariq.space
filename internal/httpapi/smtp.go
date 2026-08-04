package httpapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/riyanathariq/tools-api.riyanathariq.space/internal/auth"
	"github.com/riyanathariq/tools-api.riyanathariq.space/internal/smtp"
)

func (s *Server) handleSMTPTest(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.UserFromContext(r.Context())
	if !ok || user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthenticated"})
		return
	}

	if ok, retry := s.limiter.Allow("smtp:"+user.ID, 10, time.Hour); !ok {
		sec := int(retry.Seconds()) + 1
		w.Header().Set("Retry-After", fmt.Sprintf("%d", sec))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":         "rate limit exceeded",
			"retryAfterSec": sec,
			"limitPerHour":  10,
		})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid body"})
		return
	}
	var req smtp.Request
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
		return
	}

	// Never log password.
	s.log.Info("smtp test requested",
		"user_id", user.ID,
		"host", req.Host,
		"port", req.Port,
		"security", req.Security,
		"from", req.From,
		"to", req.To,
	)

	result := smtp.RunTest(req)
	status := http.StatusOK
	if !result.OK {
		status = http.StatusUnprocessableEntity
	}
	writeJSON(w, status, result)
}

func (s *Server) handleSMTPCheckAuth(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.UserFromContext(r.Context())
	if !ok || user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthenticated"})
		return
	}

	if ok, retry := s.limiter.Allow("smtp-auth:"+user.ID, 30, time.Hour); !ok {
		sec := int(retry.Seconds()) + 1
		w.Header().Set("Retry-After", fmt.Sprintf("%d", sec))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":         "rate limit exceeded",
			"retryAfterSec": sec,
			"limitPerHour":  30,
		})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid body"})
		return
	}
	var req smtp.AuthCheckRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
		return
	}

	s.log.Info("smtp auth check requested",
		"user_id", user.ID,
		"host", req.Host,
		"port", req.Port,
		"security", req.Security,
	)

	result := smtp.CheckAuth(req)
	status := http.StatusOK
	if !result.OK {
		status = http.StatusUnprocessableEntity
	}
	writeJSON(w, status, result)
}
