package webhook_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/riyanathariq/tools-api.riyanathariq.space/internal/db"
	"github.com/riyanathariq/tools-api.riyanathariq.space/internal/webhook"
)

func testStore(t *testing.T) *webhook.Store {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://tools:tools@127.0.0.1:5432/tools?sslmode=disable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(pool.Close)
	return webhook.NewStore(pool, nil)
}

func TestCreateIngestList(t *testing.T) {
	store := testStore(t)

	bin, err := store.Create("user-1-"+t.Name(), "Test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Delete("user-1-"+t.Name(), bin.ID) })

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

	summaries, err := store.ListHits("user-1-"+t.Name(), bin.ID, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 1 {
		t.Fatalf("hits=%d", len(summaries))
	}

	got, err := store.GetHit("user-1-"+t.Name(), bin.ID, hit.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Body != `{"hello":"world"}` {
		t.Fatalf("body=%q", got.Body)
	}
}

func TestBinLimit(t *testing.T) {
	store := testStore(t)
	user := "limit-" + t.Name()
	ids := make([]string, 0, webhook.MaxBinsPerUser)
	for i := 0; i < webhook.MaxBinsPerUser; i++ {
		b, err := store.Create(user, "")
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, b.ID)
	}
	t.Cleanup(func() {
		for _, id := range ids {
			_ = store.Delete(user, id)
		}
	})
	if _, err := store.Create(user, ""); err != webhook.ErrLimitBins {
		t.Fatalf("expected limit, got %v", err)
	}
}
