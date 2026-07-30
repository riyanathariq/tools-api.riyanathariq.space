package webhook_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/riyanathariq/tools-api.riyanathariq.space/internal/webhook"
)

func TestCreateIngestList(t *testing.T) {
	dir := t.TempDir()
	store, err := webhook.Open(filepath.Join(dir, "webhook"))
	if err != nil {
		t.Fatal(err)
	}

	bin, err := store.Create("user-1", "Test")
	if err != nil {
		t.Fatal(err)
	}
	if bin.Name != "Test" {
		t.Fatalf("name=%q", bin.Name)
	}

	hit, err := store.Ingest(bin.ID, webhook.IngestInput{
		Method:      "POST",
		Path:        "/hook/" + bin.ID + "/stripe",
		RawQuery:    "a=1",
		QueryParams: map[string]string{"a": "1"},
		Headers: map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer secret",
			"X-Custom":      "ok",
		},
		ContentType: "application/json",
		Body:        []byte(`{"hello":"world"}`),
		IP:          "1.2.3.4",
		UserAgent:   "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if hit.Headers["Authorization"] != "[redacted]" {
		t.Fatalf("auth not redacted: %#v", hit.Headers)
	}
	if hit.Headers["X-Custom"] != "ok" {
		t.Fatalf("custom header lost")
	}

	summaries, err := store.ListHits("user-1", bin.ID, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 1 {
		t.Fatalf("hits=%d", len(summaries))
	}

	got, err := store.GetHit("user-1", bin.ID, hit.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Body != `{"hello":"world"}` {
		t.Fatalf("body=%q", got.Body)
	}

	if _, err := store.GetHit("other", bin.ID, hit.ID); err != webhook.ErrForbidden {
		t.Fatalf("expected forbidden, got %v", err)
	}

	// reopen
	store2, err := webhook.Open(filepath.Join(dir, "webhook"))
	if err != nil {
		t.Fatal(err)
	}
	list := store2.List("user-1")
	if len(list) != 1 {
		t.Fatalf("reloaded bins=%d", len(list))
	}
}

func TestBinLimit(t *testing.T) {
	dir := t.TempDir()
	store, err := webhook.Open(filepath.Join(dir, "webhook"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < webhook.MaxBinsPerUser; i++ {
		if _, err := store.Create("u", ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Create("u", ""); err != webhook.ErrLimitBins {
		t.Fatalf("expected limit, got %v", err)
	}
	_ = os.RemoveAll(dir)
}
