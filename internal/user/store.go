package user

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	StatusActive = "active"
	StatusBanned = "banned"
)

var (
	ErrNotFound = errors.New("user not found")
	ErrBanned   = errors.New("user banned")
)

type User struct {
	ID          string    `json:"id"`
	Email       string    `json:"email"`
	Name        string    `json:"name"`
	Picture     string    `json:"picture,omitempty"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"createdAt"`
	LastLoginAt time.Time `json:"lastLoginAt"`
	LastLoginIP string    `json:"lastLoginIp,omitempty"`
}

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) UpsertLogin(ctx context.Context, id, email, name, picture, ip string) (*User, error) {
	now := time.Now().UTC()
	var u User
	err := s.pool.QueryRow(ctx, `
		INSERT INTO users (id, email, name, picture, status, created_at, last_login_at, last_login_ip)
		VALUES ($1, $2, $3, $4, $5, $6, $6, $7)
		ON CONFLICT (id) DO UPDATE SET
			email = EXCLUDED.email,
			name = EXCLUDED.name,
			picture = EXCLUDED.picture,
			last_login_at = EXCLUDED.last_login_at,
			last_login_ip = EXCLUDED.last_login_ip
			-- status intentionally not overwritten (preserve bans)
		RETURNING id, email, name, picture, status, created_at, last_login_at, last_login_ip
	`, id, email, name, picture, StatusActive, now, ip).Scan(
		&u.ID, &u.Email, &u.Name, &u.Picture, &u.Status, &u.CreatedAt, &u.LastLoginAt, &u.LastLoginIP,
	)
	if err != nil {
		return nil, err
	}
	if u.Status == StatusBanned {
		return &u, ErrBanned
	}
	return &u, nil
}

func (s *Store) Get(ctx context.Context, id string) (*User, error) {
	var u User
	err := s.pool.QueryRow(ctx, `
		SELECT id, email, name, picture, status, created_at, last_login_at, last_login_ip
		FROM users WHERE id = $1
	`, id).Scan(
		&u.ID, &u.Email, &u.Name, &u.Picture, &u.Status, &u.CreatedAt, &u.LastLoginAt, &u.LastLoginIP,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) IsBanned(ctx context.Context, id string) (bool, error) {
	var status string
	err := s.pool.QueryRow(ctx, `SELECT status FROM users WHERE id = $1`, id).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return status == StatusBanned, nil
}
