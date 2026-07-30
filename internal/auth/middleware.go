package auth

import (
	"context"
	"net/http"
)

type ctxKey int

const userKey ctxKey = 1

func WithUser(ctx context.Context, user *User) context.Context {
	return context.WithValue(ctx, userKey, user)
}

func UserFromContext(ctx context.Context) (*User, bool) {
	u, ok := ctx.Value(userKey).(*User)
	return u, ok && u != nil
}

func (s *SessionManager) RequireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := s.UserFromRequest(r)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthenticated"})
			return
		}
		next.ServeHTTP(w, r.WithContext(WithUser(r.Context(), user)))
	})
}
