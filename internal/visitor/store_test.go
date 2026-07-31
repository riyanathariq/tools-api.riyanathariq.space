package visitor

import "testing"

func TestFingerprintChangesWithContext(t *testing.T) {
	base := Record{
		VisitorID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		IP:        "1.2.3.4",
		Country:   "ID",
		City:      "Jakarta",
		UserAgent: "Mozilla/5.0",
		Referer:   "https://google.com/",
	}
	a := Fingerprint(base)

	ipChanged := base
	ipChanged.IP = "5.6.7.8"
	if Fingerprint(ipChanged) == a {
		t.Fatal("expected new fingerprint when IP changes")
	}

	uaChanged := base
	uaChanged.UserAgent = "curl/8.0"
	if Fingerprint(uaChanged) == a {
		t.Fatal("expected new fingerprint when user agent changes")
	}

	refChanged := base
	refChanged.Referer = "https://bing.com/"
	if Fingerprint(refChanged) == a {
		t.Fatal("expected new fingerprint when referer changes")
	}

	locChanged := base
	locChanged.City = "Bandung"
	if Fingerprint(locChanged) == a {
		t.Fatal("expected new fingerprint when city changes")
	}

	same := base
	same.SessionID = "different-session-id-xxxxx"
	same.Origin = "https://other.example"
	same.FirstPath = "/t/other"
	if Fingerprint(same) != a {
		t.Fatal("session/origin/path should not change fingerprint")
	}
}
