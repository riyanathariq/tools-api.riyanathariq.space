package smtp

import (
	"strings"
	"testing"
)

func TestLooksLikeEmail(t *testing.T) {
	ok := []string{"a@b.co", "user.name+tag@example.com"}
	bad := []string{"", "nope", "@x.com", "a@", "a@b"}
	for _, s := range ok {
		if !looksLikeEmail(s) {
			t.Fatalf("expected ok: %q", s)
		}
	}
	for _, s := range bad {
		if looksLikeEmail(s) {
			t.Fatalf("expected bad: %q", s)
		}
	}
}

func TestRunTestValidation(t *testing.T) {
	res := RunTest(Request{})
	if res.OK || res.Error == "" {
		t.Fatalf("expected validation failure, got %+v", res)
	}
}

func TestCheckAuthValidation(t *testing.T) {
	res := CheckAuth(AuthCheckRequest{})
	if res.OK || res.Error == "" {
		t.Fatalf("expected validation failure, got %+v", res)
	}
	res = CheckAuth(AuthCheckRequest{Host: "smtp.example.com", Port: 587, Username: "u"})
	if res.OK || !strings.Contains(strings.ToLower(res.Error), "password") {
		t.Fatalf("expected password required, got %+v", res)
	}
}
