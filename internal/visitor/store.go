package visitor

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

var idRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{8,128}$`)

type Record struct {
	VisitorID  string
	SessionID  string
	IP         string
	UserAgent  string
	Referer    string
	Origin     string
	Country    string
	City       string
	UserID     string
	FirstPath  string
}

type Store struct {
	pool *pgxpool.Pool
	rdb  *redis.Client
	log  *slog.Logger
}

func NewStore(pool *pgxpool.Pool, rdb *redis.Client, log *slog.Logger) *Store {
	if log == nil {
		log = slog.Default()
	}
	return &Store{pool: pool, rdb: rdb, log: log}
}

func ValidID(id string) bool {
	return idRe.MatchString(id)
}

// TrackAsync returns immediately; persistence happens in a goroutine.
func (s *Store) TrackAsync(rec Record) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.track(ctx, rec); err != nil {
			s.log.Warn("visitor track failed", "err", err, "visitor_id", rec.VisitorID)
		}
	}()
}

func (s *Store) track(ctx context.Context, rec Record) error {
	rec.VisitorID = strings.TrimSpace(rec.VisitorID)
	rec.SessionID = strings.TrimSpace(rec.SessionID)
	if !ValidID(rec.VisitorID) || !ValidID(rec.SessionID) {
		return errors.New("invalid visitor/session id")
	}
	if len(rec.FirstPath) > 512 {
		rec.FirstPath = rec.FirstPath[:512]
	}
	if len(rec.Referer) > 1024 {
		rec.Referer = rec.Referer[:1024]
	}
	if len(rec.Origin) > 512 {
		rec.Origin = rec.Origin[:512]
	}
	if len(rec.UserAgent) > 1024 {
		rec.UserAgent = rec.UserAgent[:1024]
	}

	if s.rdb != nil {
		ok, err := s.rdb.SetNX(ctx, "visitor:"+rec.VisitorID, "1", 0).Result() // forever dedupe marker
		if err != nil {
			// Valkey down: still try PG insert-or-update
			return s.persist(ctx, rec, true)
		}
		if !ok {
			return s.updateSeen(ctx, rec)
		}
		if err := s.insert(ctx, rec); err != nil {
			return s.updateSeen(ctx, rec)
		}
		return nil
	}
	return s.persist(ctx, rec, true)
}

func (s *Store) persist(ctx context.Context, rec Record, allowInsert bool) error {
	if allowInsert {
		if err := s.insert(ctx, rec); err == nil {
			return nil
		}
	}
	return s.updateSeen(ctx, rec)
}

func (s *Store) insert(ctx context.Context, rec Record) error {
	now := time.Now().UTC()
	var userID any
	if rec.UserID != "" {
		userID = rec.UserID
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO visitors (
			visitor_id, session_id, ip, user_agent, referer, origin,
			country, city, user_id, first_seen_at, last_seen_at, first_path
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10,$11)
	`, rec.VisitorID, rec.SessionID, rec.IP, rec.UserAgent, rec.Referer, rec.Origin,
		rec.Country, rec.City, userID, now, rec.FirstPath)
	return err
}

func (s *Store) updateSeen(ctx context.Context, rec Record) error {
	now := time.Now().UTC()
	if rec.UserID != "" {
		_, err := s.pool.Exec(ctx, `
			UPDATE visitors
			SET last_seen_at = $2,
			    session_id = $3,
			    user_id = COALESCE(user_id, $4)
			WHERE visitor_id = $1
		`, rec.VisitorID, now, rec.SessionID, rec.UserID)
		return err
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE visitors
		SET last_seen_at = $2,
		    session_id = $3
		WHERE visitor_id = $1
	`, rec.VisitorID, now, rec.SessionID)
	return err
}
