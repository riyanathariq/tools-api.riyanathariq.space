package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionIssueAndParse(t *testing.T) {
	sm := NewSessionManager("12345678901234567890123456789012", "tools_session", false, time.Hour)
	rec := httptest.NewRecorder()
	user := User{ID: "u1", Email: "a@b.c", Name: "A"}
	if err := sm.Issue(rec, user); err != nil {
		t.Fatalf("issue: %v", err)
	}
	res := rec.Result()
	cookies := res.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(cookies[0])
	got, err := sm.UserFromRequest(req)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.ID != user.ID || got.Email != user.Email {
		t.Fatalf("unexpected user: %+v", got)
	}
}

func TestSanitizeNext(t *testing.T) {
	cases := map[string]string{
		"":                         "/",
		"/t/smtp-tester":           "/t/smtp-tester",
		"//evil.com":               "/",
		"https://evil.com":         "/",
		"/ok?x=1":                  "/ok?x=1",
		"relative":                 "/",
		"/has\nnewline":            "/",
	}
	for in, want := range cases {
		if got := sanitizeNext(in); got != want {
			t.Fatalf("sanitizeNext(%q)=%q want %q", in, got, want)
		}
	}
}
