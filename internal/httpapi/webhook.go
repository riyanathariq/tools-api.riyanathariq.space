package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/riyanathariq/tools-api.riyanathariq.space/internal/auth"
	"github.com/riyanathariq/tools-api.riyanathariq.space/internal/webhook"
)

func (s *Server) handleCreateBin(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.UserFromContext(r.Context())
	if !ok || user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthenticated"})
		return
	}
	if ok, retry := s.limiter.Allow("webhook:create:"+user.ID, 20, time.Hour); !ok {
		sec := int(retry.Seconds()) + 1
		w.Header().Set("Retry-After", fmt.Sprintf("%d", sec))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":         "rate limit exceeded",
			"retryAfterSec": sec,
		})
		return
	}

	var body struct {
		Name string `json:"name"`
	}
	_ = decodeJSONLimited(r, 4<<10, &body)

	bin, err := s.hooks.Create(user.ID, body.Name)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, webhook.ErrLimitBins) {
			status = http.StatusConflict
		}
		writeJSON(w, status, map[string]any{"error": webhook.FormatLimitErr(err)})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"bin":     bin,
		"hookUrl": s.hookURL(bin.ID),
		"limits":  webhookLimits(),
	})
}

func (s *Server) handleListBins(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.UserFromContext(r.Context())
	if !ok || user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthenticated"})
		return
	}
	bins := s.hooks.List(user.ID)
	items := make([]map[string]any, 0, len(bins))
	for _, b := range bins {
		items = append(items, map[string]any{
			"bin":     b,
			"hookUrl": s.hookURL(b.ID),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"bins":   items,
		"limits": webhookLimits(),
	})
}

func (s *Server) handleGetBin(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.UserFromContext(r.Context())
	if !ok || user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthenticated"})
		return
	}
	binID := r.PathValue("id")
	bin, err := s.hooks.Get(user.ID, binID)
	if err != nil {
		writeWebhookErr(w, err)
		return
	}
	hits, err := s.hooks.ListHits(user.ID, binID, webhook.MaxHitsPerBin, "")
	if err != nil {
		writeWebhookErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"bin":     bin,
		"hookUrl": s.hookURL(bin.ID),
		"hits":    hits,
		"limits":  webhookLimits(),
	})
}

func (s *Server) handleDeleteBin(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.UserFromContext(r.Context())
	if !ok || user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthenticated"})
		return
	}
	if err := s.hooks.Delete(user.ID, r.PathValue("id")); err != nil {
		writeWebhookErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleClearHits(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.UserFromContext(r.Context())
	if !ok || user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthenticated"})
		return
	}
	bin, err := s.hooks.ClearHits(user.ID, r.PathValue("id"))
	if err != nil {
		writeWebhookErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":  true,
		"bin": bin,
	})
}

func (s *Server) handleListHits(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.UserFromContext(r.Context())
	if !ok || user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthenticated"})
		return
	}
	binID := r.PathValue("id")
	after := r.URL.Query().Get("after")
	hits, err := s.hooks.ListHits(user.ID, binID, webhook.MaxHitsPerBin, after)
	if err != nil {
		writeWebhookErr(w, err)
		return
	}
	bin, err := s.hooks.Get(user.ID, binID)
	if err != nil {
		writeWebhookErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"bin":  bin,
		"hits": hits,
	})
}

func (s *Server) handleGetHit(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.UserFromContext(r.Context())
	if !ok || user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthenticated"})
		return
	}
	hit, err := s.hooks.GetHit(user.ID, r.PathValue("id"), r.PathValue("hitId"))
	if err != nil {
		writeWebhookErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hit": hit})
}

func (s *Server) handleHookIngest(w http.ResponseWriter, r *http.Request) {
	binID := r.PathValue("id")
	if binID == "" || !looksLikeBinID(binID) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	if !s.hooks.PublicExists(binID) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}

	if ok, retry := s.limiter.Allow("hook:"+binID, 120, time.Minute); !ok {
		sec := int(retry.Seconds()) + 1
		w.Header().Set("Retry-After", fmt.Sprintf("%d", sec))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":         "rate limit exceeded",
			"retryAfterSec": sec,
		})
		return
	}

	// HEAD / OPTIONS-ish: don't store, just confirm the bin exists.
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, webhook.MaxBodyBytes+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid body"})
		return
	}
	if len(body) > webhook.MaxBodyBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
			"error":   "body too large",
			"maxBytes": webhook.MaxBodyBytes,
		})
		return
	}

	pathExtra := r.PathValue("path")
	path := "/hook/" + binID
	if pathExtra != "" {
		path += "/" + pathExtra
	}

	headers := map[string]string{}
	for k, vals := range r.Header {
		if len(vals) == 0 {
			continue
		}
		headers[k] = strings.Join(vals, ", ")
	}
	q := map[string]string{}
	for k, vals := range r.URL.Query() {
		if len(vals) > 0 {
			q[k] = vals[0]
		}
	}

	hit, err := s.hooks.Ingest(binID, webhook.IngestInput{
		Method:      r.Method,
		Path:        path,
		RawQuery:    r.URL.RawQuery,
		QueryParams: q,
		Headers:     headers,
		ContentType: r.Header.Get("Content-Type"),
		Body:        body,
		IP:          clientIP(r),
		UserAgent:   r.UserAgent(),
	})
	if err != nil {
		writeWebhookErr(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":  true,
		"id":  hit.ID,
		"bin": binID,
	})
}

func (s *Server) hookURL(binID string) string {
	base := strings.TrimRight(s.cfg.FrontendURL, "/")
	if base == "" {
		base = strings.TrimRight(s.cfg.PublicBaseURL, "/")
	}
	return base + "/hook/" + binID
}

func webhookLimits() map[string]any {
	return map[string]any{
		"maxBinsPerUser": webhook.MaxBinsPerUser,
		"maxHitsPerBin":  webhook.MaxHitsPerBin,
		"maxBodyBytes":   webhook.MaxBodyBytes,
		"ttlHours":       int(webhook.BinTTL.Hours()),
	}
}

func writeWebhookErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, webhook.ErrNotFound), errors.Is(err, webhook.ErrExpired):
		writeJSON(w, http.StatusNotFound, map[string]any{"error": webhook.FormatLimitErr(err)})
	case errors.Is(err, webhook.ErrForbidden):
		writeJSON(w, http.StatusForbidden, map[string]any{"error": webhook.FormatLimitErr(err)})
	case errors.Is(err, webhook.ErrLimitBins):
		writeJSON(w, http.StatusConflict, map[string]any{"error": webhook.FormatLimitErr(err)})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": webhook.FormatLimitErr(err)})
	}
}

func looksLikeBinID(id string) bool {
	if len(id) != webhook.IDBytes*2 {
		return false
	}
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func decodeJSONLimited(r *http.Request, max int64, dst any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, max))
	return dec.Decode(dst)
}
