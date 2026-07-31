package webhook

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
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
	ID        string     `json:"id"`
	UserID    string     `json:"userId"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"createdAt"`
	ExpiresAt time.Time  `json:"expiresAt"`
	HitCount  int        `json:"hitCount"`
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
	ID          string    `json:"id"`
	ReceivedAt  time.Time `json:"receivedAt"`
	Method      string    `json:"method"`
	Path        string    `json:"path"`
	Query       string    `json:"query,omitempty"`
	ContentType string    `json:"contentType,omitempty"`
	BodyBytes   int       `json:"bodyBytes"`
	IP          string    `json:"ip"`
}

type Store struct {
	pool *pgxpool.Pool
	rdb  *redis.Client
}

func NewStore(pool *pgxpool.Pool, rdb *redis.Client) *Store {
	return &Store{pool: pool, rdb: rdb}
}

func binCacheKey(id string) string { return "bin:" + id }

func (s *Store) cacheBin(ctx context.Context, id string, ttl time.Duration) {
	if s.rdb == nil || ttl <= 0 {
		return
	}
	_ = s.rdb.Set(ctx, binCacheKey(id), "1", ttl).Err()
}

func (s *Store) uncacheBin(ctx context.Context, id string) {
	if s.rdb == nil {
		return
	}
	_ = s.rdb.Del(ctx, binCacheKey(id)).Err()
}

func newID() (string, error) {
	var b [IDBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func (s *Store) Create(userID, name string) (*Bin, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.pruneExpired(ctx); err != nil {
		return nil, err
	}

	var count int
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM webhook_bins WHERE user_id = $1`, userID).Scan(&count); err != nil {
		return nil, err
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
	now := time.Now().UTC()
	bin := &Bin{
		ID:        id,
		UserID:    userID,
		Name:      name,
		CreatedAt: now,
		ExpiresAt: now.Add(BinTTL),
		HitCount:  0,
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO webhook_bins (id, user_id, name, created_at, expires_at, hit_count)
		VALUES ($1, $2, $3, $4, $5, 0)
	`, bin.ID, bin.UserID, bin.Name, bin.CreatedAt, bin.ExpiresAt)
	if err != nil {
		return nil, err
	}
	s.cacheBin(ctx, bin.ID, BinTTL)
	return bin, nil
}

func (s *Store) List(userID string) []Bin {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.pruneExpired(ctx)

	rows, err := s.pool.Query(ctx, `
		SELECT id, user_id, name, created_at, expires_at, hit_count, last_hit_at
		FROM webhook_bins
		WHERE user_id = $1
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	out := make([]Bin, 0)
	for rows.Next() {
		b, err := scanBin(rows)
		if err != nil {
			continue
		}
		out = append(out, b)
	}
	return out
}

func (s *Store) Get(userID, binID string) (*Bin, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.pruneExpired(ctx)
	return s.getOwned(ctx, userID, binID)
}

func (s *Store) Delete(userID, binID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.getOwned(ctx, userID, binID); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM webhook_bins WHERE id = $1`, binID)
	if err == nil {
		s.uncacheBin(ctx, binID)
	}
	return err
}

func (s *Store) ClearHits(userID, binID string) (*Bin, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.getOwned(ctx, userID, binID); err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM webhook_hits WHERE bin_id = $1`, binID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE webhook_bins SET hit_count = 0, last_hit_at = NULL WHERE id = $1
	`, binID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.getOwned(ctx, userID, binID)
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
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_ = s.pruneExpired(ctx)

	var expiresAt time.Time
	err := s.pool.QueryRow(ctx, `SELECT expires_at FROM webhook_bins WHERE id = $1`, binID).Scan(&expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if now.After(expiresAt) {
		_, _ = s.pool.Exec(ctx, `DELETE FROM webhook_bins WHERE id = $1`, binID)
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
	if in.QueryParams == nil {
		in.QueryParams = map[string]string{}
	}
	headers := redactHeaders(in.Headers)
	qpJSON, _ := json.Marshal(in.QueryParams)
	hJSON, _ := json.Marshal(headers)

	hit := &Hit{
		ID:          hitID,
		BinID:       binID,
		ReceivedAt:  now,
		Method:      strings.ToUpper(strings.TrimSpace(in.Method)),
		Path:        in.Path,
		Query:       in.RawQuery,
		QueryParams: in.QueryParams,
		Headers:     headers,
		ContentType: in.ContentType,
		Body:        string(body),
		BodyTrunc:   trunc,
		BodyBytes:   len(in.Body),
		IP:          in.IP,
		UserAgent:   in.UserAgent,
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		INSERT INTO webhook_hits (
			id, bin_id, received_at, method, path, query, query_params, headers,
			content_type, body, body_truncated, body_bytes, ip, user_agent
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14
		)
	`, hit.ID, hit.BinID, hit.ReceivedAt, hit.Method, hit.Path, hit.Query, qpJSON, hJSON,
		hit.ContentType, hit.Body, hit.BodyTrunc, hit.BodyBytes, hit.IP, hit.UserAgent)
	if err != nil {
		return nil, err
	}

	// Cap to newest MaxHitsPerBin.
	_, err = tx.Exec(ctx, `
		DELETE FROM webhook_hits
		WHERE bin_id = $1
		  AND id IN (
			SELECT id FROM webhook_hits
			WHERE bin_id = $1
			ORDER BY received_at DESC
			OFFSET $2
		  )
	`, binID, MaxHitsPerBin)
	if err != nil {
		return nil, err
	}

	var hitCount int
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM webhook_hits WHERE bin_id = $1`, binID).Scan(&hitCount); err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx, `
		UPDATE webhook_bins SET hit_count = $2, last_hit_at = $3 WHERE id = $1
	`, binID, hitCount, now)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return hit, nil
}

func (s *Store) ListHits(userID, binID string, limit int, after string) ([]HitSummary, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.getOwned(ctx, userID, binID); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > MaxHitsPerBin {
		limit = MaxHitsPerBin
	}

	var rows pgx.Rows
	var err error
	if after == "" {
		rows, err = s.pool.Query(ctx, `
			SELECT id, received_at, method, path, query, content_type, body_bytes, ip
			FROM webhook_hits
			WHERE bin_id = $1
			ORDER BY received_at DESC
			LIMIT $2
		`, binID, limit)
	} else {
		rows, err = s.pool.Query(ctx, `
			SELECT id, received_at, method, path, query, content_type, body_bytes, ip
			FROM webhook_hits
			WHERE bin_id = $1
			  AND received_at < (
				SELECT received_at FROM webhook_hits WHERE id = $2 AND bin_id = $1
			  )
			ORDER BY received_at DESC
			LIMIT $3
		`, binID, after, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]HitSummary, 0, limit)
	for rows.Next() {
		var h HitSummary
		if err := rows.Scan(&h.ID, &h.ReceivedAt, &h.Method, &h.Path, &h.Query, &h.ContentType, &h.BodyBytes, &h.IP); err != nil {
			continue
		}
		out = append(out, h)
	}
	return out, nil
}

func (s *Store) GetHit(userID, binID, hitID string) (*Hit, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.getOwned(ctx, userID, binID); err != nil {
		return nil, err
	}

	var (
		h       Hit
		qpRaw   []byte
		hdrRaw  []byte
	)
	err := s.pool.QueryRow(ctx, `
		SELECT id, bin_id, received_at, method, path, query, query_params, headers,
		       content_type, body, body_truncated, body_bytes, ip, user_agent
		FROM webhook_hits
		WHERE id = $1 AND bin_id = $2
	`, hitID, binID).Scan(
		&h.ID, &h.BinID, &h.ReceivedAt, &h.Method, &h.Path, &h.Query, &qpRaw, &hdrRaw,
		&h.ContentType, &h.Body, &h.BodyTrunc, &h.BodyBytes, &h.IP, &h.UserAgent,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(qpRaw, &h.QueryParams)
	_ = json.Unmarshal(hdrRaw, &h.Headers)
	if h.QueryParams == nil {
		h.QueryParams = map[string]string{}
	}
	if h.Headers == nil {
		h.Headers = map[string]string{}
	}
	return &h, nil
}

func (s *Store) PublicExists(binID string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if s.rdb != nil {
		n, err := s.rdb.Exists(ctx, binCacheKey(binID)).Result()
		if err == nil && n > 0 {
			return true
		}
	}
	_ = s.pruneExpired(ctx)
	var expiresAt time.Time
	err := s.pool.QueryRow(ctx, `SELECT expires_at FROM webhook_bins WHERE id = $1`, binID).Scan(&expiresAt)
	if err != nil {
		return false
	}
	if time.Now().UTC().After(expiresAt) {
		s.uncacheBin(ctx, binID)
		return false
	}
	s.cacheBin(ctx, binID, time.Until(expiresAt))
	return true
}

func (s *Store) getOwned(ctx context.Context, userID, binID string) (*Bin, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, user_id, name, created_at, expires_at, hit_count, last_hit_at
		FROM webhook_bins WHERE id = $1
	`, binID)
	b, err := scanBin(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if b.UserID != userID {
		return nil, ErrForbidden
	}
	if time.Now().UTC().After(b.ExpiresAt) {
		_, _ = s.pool.Exec(ctx, `DELETE FROM webhook_bins WHERE id = $1`, binID)
		s.uncacheBin(ctx, binID)
		return nil, ErrExpired
	}
	return &b, nil
}

type scannable interface {
	Scan(dest ...any) error
}

func scanBin(row scannable) (Bin, error) {
	var b Bin
	var lastHit *time.Time
	err := row.Scan(&b.ID, &b.UserID, &b.Name, &b.CreatedAt, &b.ExpiresAt, &b.HitCount, &lastHit)
	if err != nil {
		return Bin{}, err
	}
	b.LastHitAt = lastHit
	return b, nil
}

func (s *Store) pruneExpired(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `DELETE FROM webhook_bins WHERE expires_at < NOW() RETURNING id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			s.uncacheBin(ctx, id)
		}
	}
	return rows.Err()
}

func redactHeaders(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		switch strings.ToLower(k) {
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
