package webhook

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	MaxBinsPerUser = 3
	MaxHitsPerBin  = 100
	MaxBodyBytes   = 256 << 10 // 256 KiB
	BinTTL         = 72 * time.Hour
	IDBytes        = 16
)

var (
	ErrNotFound     = errors.New("not found")
	ErrForbidden    = errors.New("forbidden")
	ErrLimitBins    = errors.New("bin limit reached")
	ErrExpired      = errors.New("bin expired")
	ErrBodyTooLarge = errors.New("body too large")
)

type Bin struct {
	ID        string    `json:"id"`
	UserID    string    `json:"userId"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	HitCount  int       `json:"hitCount"`
	LastHitAt *time.Time `json:"lastHitAt,omitempty"`
}

type Hit struct {
	ID          string            `json:"id"`
	BinID       string            `json:"binId"`
	ReceivedAt  time.Time         `json:"receivedAt"`
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	Query       string            `json:"query,omitempty"`
	QueryParams map[string]string `json:"queryParams,omitempty"`
	Headers     map[string]string `json:"headers"`
	ContentType string            `json:"contentType,omitempty"`
	Body        string            `json:"body"`
	BodyTrunc   bool              `json:"bodyTruncated"`
	BodyBytes   int               `json:"bodyBytes"`
	IP          string            `json:"ip"`
	UserAgent   string            `json:"userAgent,omitempty"`
}

type HitSummary struct {
	ID         string    `json:"id"`
	ReceivedAt time.Time `json:"receivedAt"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	Query      string    `json:"query,omitempty"`
	ContentType string   `json:"contentType,omitempty"`
	BodyBytes  int       `json:"bodyBytes"`
	IP         string    `json:"ip"`
}

type Store struct {
	mu   sync.Mutex
	dir  string
	bins map[string]*Bin
	// hitIDs newest-first per bin
	order map[string][]string
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "meta"), 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, "hits"), 0o755); err != nil {
		return nil, err
	}
	s := &Store{
		dir:   dir,
		bins:  map[string]*Bin{},
		order: map[string][]string{},
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	s.pruneExpiredLocked(time.Now().UTC())
	return s, nil
}

func (s *Store) load() error {
	entries, err := os.ReadDir(filepath.Join(s.dir, "meta"))
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(s.dir, "meta", e.Name()))
		if err != nil {
			continue
		}
		var b Bin
		if err := json.Unmarshal(raw, &b); err != nil {
			continue
		}
		s.bins[b.ID] = &b
		s.order[b.ID] = s.listHitIDs(b.ID)
	}
	return nil
}

func (s *Store) listHitIDs(binID string) []string {
	dir := filepath.Join(s.dir, "hits", binID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	type item struct {
		id string
		t  time.Time
	}
	items := make([]item, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		h, err := s.readHitFile(binID, id)
		if err != nil {
			continue
		}
		items = append(items, item{id: id, t: h.ReceivedAt})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].t.After(items[j].t)
	})
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.id
	}
	return out
}

func newID() (string, error) {
	var b [IDBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func (s *Store) Create(userID, name string) (*Bin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	s.pruneExpiredLocked(now)

	count := 0
	for _, b := range s.bins {
		if b.UserID == userID {
			count++
		}
	}
	if count >= MaxBinsPerUser {
		return nil, ErrLimitBins
	}

	id, err := newID()
	if err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Bin " + id[:6]
	}
	if len(name) > 64 {
		name = name[:64]
	}
	bin := &Bin{
		ID:        id,
		UserID:    userID,
		Name:      name,
		CreatedAt: now,
		ExpiresAt: now.Add(BinTTL),
		HitCount:  0,
	}
	if err := s.writeBinLocked(bin); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(s.dir, "hits", id), 0o755); err != nil {
		return nil, err
	}
	s.bins[id] = bin
	s.order[id] = nil
	cp := *bin
	return &cp, nil
}

func (s *Store) List(userID string) []Bin {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	s.pruneExpiredLocked(now)

	out := make([]Bin, 0)
	for _, b := range s.bins {
		if b.UserID == userID {
			out = append(out, *b)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out
}

func (s *Store) Get(userID, binID string) (*Bin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	s.pruneExpiredLocked(now)
	b, err := s.getOwnedLocked(userID, binID)
	if err != nil {
		return nil, err
	}
	cp := *b
	return &cp, nil
}

func (s *Store) Delete(userID, binID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.getOwnedLocked(userID, binID)
	if err != nil {
		return err
	}
	return s.deleteBinLocked(b.ID)
}

func (s *Store) ClearHits(userID, binID string) (*Bin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.getOwnedLocked(userID, binID)
	if err != nil {
		return nil, err
	}
	_ = os.RemoveAll(filepath.Join(s.dir, "hits", binID))
	_ = os.MkdirAll(filepath.Join(s.dir, "hits", binID), 0o755)
	s.order[binID] = nil
	b.HitCount = 0
	b.LastHitAt = nil
	if err := s.writeBinLocked(b); err != nil {
		return nil, err
	}
	cp := *b
	return &cp, nil
}

type IngestInput struct {
	Method      string
	Path        string
	RawQuery    string
	QueryParams map[string]string
	Headers     map[string]string
	ContentType string
	Body        []byte
	IP          string
	UserAgent   string
}

func (s *Store) Ingest(binID string, in IngestInput) (*Hit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	s.pruneExpiredLocked(now)

	b, ok := s.bins[binID]
	if !ok {
		return nil, ErrNotFound
	}
	if now.After(b.ExpiresAt) {
		_ = s.deleteBinLocked(binID)
		return nil, ErrExpired
	}

	body := in.Body
	trunc := false
	if len(body) > MaxBodyBytes {
		body = body[:MaxBodyBytes]
		trunc = true
	}

	hitID, err := newID()
	if err != nil {
		return nil, err
	}
	hit := &Hit{
		ID:          hitID,
		BinID:       binID,
		ReceivedAt:  now,
		Method:      strings.ToUpper(strings.TrimSpace(in.Method)),
		Path:        in.Path,
		Query:       in.RawQuery,
		QueryParams: in.QueryParams,
		Headers:     redactHeaders(in.Headers),
		ContentType: in.ContentType,
		Body:        string(body),
		BodyTrunc:   trunc,
		BodyBytes:   len(in.Body),
		IP:          in.IP,
		UserAgent:   in.UserAgent,
	}
	if err := s.writeHitLocked(hit); err != nil {
		return nil, err
	}

	order := append([]string{hitID}, s.order[binID]...)
	for len(order) > MaxHitsPerBin {
		old := order[len(order)-1]
		order = order[:len(order)-1]
		_ = os.Remove(filepath.Join(s.dir, "hits", binID, old+".json"))
	}
	s.order[binID] = order
	b.HitCount = len(order)
	t := now
	b.LastHitAt = &t
	if err := s.writeBinLocked(b); err != nil {
		return nil, err
	}
	cp := *hit
	return &cp, nil
}

func (s *Store) ListHits(userID, binID string, limit int, after string) ([]HitSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	s.pruneExpiredLocked(now)
	if _, err := s.getOwnedLocked(userID, binID); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > MaxHitsPerBin {
		limit = MaxHitsPerBin
	}
	order := s.order[binID]
	out := make([]HitSummary, 0, limit)
	skip := after != ""
	for _, id := range order {
		if skip {
			if id == after {
				skip = false
			}
			continue
		}
		h, err := s.readHitFile(binID, id)
		if err != nil {
			continue
		}
		out = append(out, HitSummary{
			ID:          h.ID,
			ReceivedAt:  h.ReceivedAt,
			Method:      h.Method,
			Path:        h.Path,
			Query:       h.Query,
			ContentType: h.ContentType,
			BodyBytes:   h.BodyBytes,
			IP:          h.IP,
		})
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *Store) GetHit(userID, binID, hitID string) (*Hit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	s.pruneExpiredLocked(now)
	if _, err := s.getOwnedLocked(userID, binID); err != nil {
		return nil, err
	}
	h, err := s.readHitFile(binID, hitID)
	if err != nil {
		return nil, ErrNotFound
	}
	return h, nil
}

func (s *Store) PublicExists(binID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	s.pruneExpiredLocked(now)
	b, ok := s.bins[binID]
	return ok && now.Before(b.ExpiresAt)
}

func (s *Store) getOwnedLocked(userID, binID string) (*Bin, error) {
	b, ok := s.bins[binID]
	if !ok {
		return nil, ErrNotFound
	}
	if b.UserID != userID {
		return nil, ErrForbidden
	}
	if time.Now().UTC().After(b.ExpiresAt) {
		_ = s.deleteBinLocked(binID)
		return nil, ErrExpired
	}
	return b, nil
}

func (s *Store) writeBinLocked(b *Bin) error {
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(s.dir, "meta", b.ID+".json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Store) writeHitLocked(h *Hit) error {
	dir := filepath.Join(s.dir, "hits", h.BinID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, h.ID+".json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Store) readHitFile(binID, hitID string) (*Hit, error) {
	raw, err := os.ReadFile(filepath.Join(s.dir, "hits", binID, hitID+".json"))
	if err != nil {
		return nil, err
	}
	var h Hit
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, err
	}
	return &h, nil
}

func (s *Store) deleteBinLocked(binID string) error {
	delete(s.bins, binID)
	delete(s.order, binID)
	_ = os.Remove(filepath.Join(s.dir, "meta", binID+".json"))
	_ = os.RemoveAll(filepath.Join(s.dir, "hits", binID))
	return nil
}

func (s *Store) pruneExpiredLocked(now time.Time) {
	for id, b := range s.bins {
		if now.After(b.ExpiresAt) {
			_ = s.deleteBinLocked(id)
		}
	}
}

func redactHeaders(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		lk := strings.ToLower(k)
		switch lk {
		case "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token":
			out[k] = "[redacted]"
		default:
			out[k] = v
		}
	}
	return out
}

func FormatLimitErr(err error) string {
	switch {
	case errors.Is(err, ErrLimitBins):
		return fmt.Sprintf("Limit reached: max %d active bins", MaxBinsPerUser)
	case errors.Is(err, ErrExpired):
		return "Bin expired"
	case errors.Is(err, ErrNotFound):
		return "Not found"
	case errors.Is(err, ErrForbidden):
		return "Forbidden"
	case errors.Is(err, ErrBodyTooLarge):
		return "Body too large"
	default:
		return err.Error()
	}
}
