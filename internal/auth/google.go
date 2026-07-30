package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	oauthStateCookie = "oauth_state"
	oauthNextCookie  = "oauth_next"
)

type GoogleAuth struct {
	cfg      *oauth2.Config
	sessions *SessionManager
	frontURL string
	http     *http.Client
	log      *slog.Logger
}

func NewGoogleAuth(clientID, clientSecret, publicBaseURL, frontendURL string, sessions *SessionManager, log *slog.Logger) *GoogleAuth {
	redirect := strings.TrimRight(publicBaseURL, "/") + "/auth/google/callback"
	if log == nil {
		log = slog.Default()
	}
	return &GoogleAuth{
		cfg: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirect,
			Scopes:       []string{"openid", "email", "profile"},
			Endpoint:     google.Endpoint,
		},
		sessions: sessions,
		frontURL: strings.TrimRight(frontendURL, "/"),
		http:     &http.Client{Timeout: 15 * time.Second},
		log:      log,
	}
}

func (g *GoogleAuth) Enabled() bool {
	return g != nil && g.cfg.ClientID != "" && g.cfg.ClientSecret != ""
}

func (g *GoogleAuth) Begin(w http.ResponseWriter, r *http.Request) {
	if !g.Enabled() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "Google OAuth is not configured",
		})
		return
	}

	state, err := randomState(32)
	if err != nil {
		g.log.Error("oauth state generation failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to start login"})
		return
	}

	next := sanitizeNext(r.URL.Query().Get("next"))
	g.setShortCookie(w, oauthStateCookie, state, 10*time.Minute)
	g.setShortCookie(w, oauthNextCookie, next, 10*time.Minute)

	authURL := g.cfg.AuthCodeURL(state, oauth2.AccessTypeOnline, oauth2.SetAuthURLParam("prompt", "select_account"))
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (g *GoogleAuth) Callback(w http.ResponseWriter, r *http.Request) {
	if !g.Enabled() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "Google OAuth is not configured",
		})
		return
	}

	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		g.log.Warn("google oauth error", "error", errMsg)
		http.Redirect(w, r, g.frontURL+"/login?error="+url.QueryEscape(errMsg), http.StatusFound)
		return
	}

	stateCookie, err := r.Cookie(oauthStateCookie)
	if err != nil || stateCookie.Value == "" || stateCookie.Value != r.URL.Query().Get("state") {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid oauth state"})
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing code"})
		return
	}

	tok, err := g.cfg.Exchange(r.Context(), code)
	if err != nil {
		g.log.Error("token exchange failed", "err", err)
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "token exchange failed"})
		return
	}

	user, err := g.fetchUser(r.Context(), tok.AccessToken)
	if err != nil {
		g.log.Error("fetch google profile failed", "err", err)
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "failed to fetch profile"})
		return
	}

	if err := g.sessions.Issue(w, *user); err != nil {
		g.log.Error("session issue failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to create session"})
		return
	}

	next := "/"
	if c, err := r.Cookie(oauthNextCookie); err == nil {
		next = sanitizeNext(c.Value)
	}
	g.clearCookie(w, oauthStateCookie)
	g.clearCookie(w, oauthNextCookie)
	http.Redirect(w, r, g.frontURL+next, http.StatusFound)
}

func (g *GoogleAuth) Me(w http.ResponseWriter, r *http.Request) {
	user, err := g.sessions.UserFromRequest(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthenticated"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

func (g *GoogleAuth) Logout(w http.ResponseWriter, r *http.Request) {
	g.sessions.Clear(w)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (g *GoogleAuth) Status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"googleConfigured": g.Enabled(),
	})
}

func (g *GoogleAuth) fetchUser(ctx context.Context, accessToken string) (*User, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://openidconnect.googleapis.com/v1/userinfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	res, err := g.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 300 {
		return nil, fmt.Errorf("userinfo status %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
	}

	var raw struct {
		Sub     string `json:"sub"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	if raw.Sub == "" || raw.Email == "" {
		return nil, errors.New("incomplete google profile")
	}
	return &User{
		ID:      raw.Sub,
		Email:   raw.Email,
		Name:    raw.Name,
		Picture: raw.Picture,
	}, nil
}

func (g *GoogleAuth) setShortCookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   g.sessions.Secure(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
}

func (g *GoogleAuth) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   g.sessions.Secure(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func sanitizeNext(next string) string {
	next = strings.TrimSpace(next)
	if next == "" {
		return "/"
	}
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "/"
	}
	if strings.ContainsAny(next, "\r\n") {
		return "/"
	}
	u, err := url.Parse(next)
	if err != nil || u.Host != "" || u.Scheme != "" {
		return "/"
	}
	return next
}

func randomState(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
