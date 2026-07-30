package smtp

import "testing"

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
