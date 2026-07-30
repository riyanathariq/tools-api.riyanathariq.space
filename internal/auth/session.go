package auth

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type User struct {
	ID      string `json:"id"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture,omitempty"`
}

type Claims struct {
	UID     string `json:"uid"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture,omitempty"`
	jwt.RegisteredClaims
}

type SessionManager struct {
	secret   []byte
	cookie   string
	secure   bool
	ttl      time.Duration
	sameSite http.SameSite
}

func NewSessionManager(secret, cookieName string, secure bool, ttl time.Duration) *SessionManager {
	return &SessionManager{
		secret:   []byte(secret),
		cookie:   cookieName,
		secure:   secure,
		ttl:      ttl,
		sameSite: http.SameSiteLaxMode,
	}
}

func (s *SessionManager) CookieName() string { return s.cookie }
func (s *SessionManager) Secure() bool       { return s.secure }

func (s *SessionManager) Issue(w http.ResponseWriter, user User) error {
	if user.ID == "" || user.Email == "" {
		return errors.New("invalid user for session")
	}
	now := time.Now()
	claims := Claims{
		UID:     user.ID,
		Email:   user.Email,
		Name:    user.Name,
		Picture: user.Picture,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.ttl)),
			Issuer:    "tools-api.riyanathariq.space",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(s.secret)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookie,
		Value:    signed,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: s.sameSite,
		MaxAge:   int(s.ttl.Seconds()),
	})
	return nil
}

func (s *SessionManager) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: s.sameSite,
		MaxAge:   -1,
	})
}

func (s *SessionManager) UserFromRequest(r *http.Request) (*User, error) {
	c, err := r.Cookie(s.cookie)
	if err != nil || c.Value == "" {
		return nil, errors.New("unauthenticated")
	}
	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(c.Value, claims, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return s.secret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil || !parsed.Valid {
		return nil, errors.New("invalid session")
	}
	uid := claims.UID
	if uid == "" {
		uid = claims.Subject
	}
	if uid == "" || claims.Email == "" {
		return nil, errors.New("invalid session claims")
	}
	return &User{
		ID:      uid,
		Email:   claims.Email,
		Name:    claims.Name,
		Picture: claims.Picture,
	}, nil
}
