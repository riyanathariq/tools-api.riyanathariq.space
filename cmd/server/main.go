package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"

	"github.com/riyanathariq/tools-api.riyanathariq.space/internal/auth"
	"github.com/riyanathariq/tools-api.riyanathariq.space/internal/config"
	"github.com/riyanathariq/tools-api.riyanathariq.space/internal/db"
	"github.com/riyanathariq/tools-api.riyanathariq.space/internal/httpapi"
	"github.com/riyanathariq/tools-api.riyanathariq.space/internal/ratelimit"
	"github.com/riyanathariq/tools-api.riyanathariq.space/internal/user"
	"github.com/riyanathariq/tools-api.riyanathariq.space/internal/visitor"
	"github.com/riyanathariq/tools-api.riyanathariq.space/internal/webhook"
)

func main() {
	_ = godotenv.Load()

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load()
	if err != nil {
		log.Error("invalid config", "err", err)
		os.Exit(1)
	}

	bootCtx, bootCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer bootCancel()

	pool, err := db.Connect(bootCtx, cfg.DatabaseURL)
	if err != nil {
		log.Error("postgres", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	rdb, err := ratelimit.ConnectValkey(bootCtx, cfg.ValkeyURL)
	if err != nil {
		log.Error("valkey", "err", err)
		os.Exit(1)
	}
	defer rdb.Close()

	users := user.NewStore(pool)
	visitors := visitor.NewStore(pool, rdb, log)
	hooks := webhook.NewStore(pool, rdb)
	limiter := ratelimit.New(rdb)

	sessions := auth.NewSessionManager(cfg.SessionSecret, cfg.CookieName, cfg.CookieSecure, cfg.SessionTTL)
	google := auth.NewGoogleAuth(
		cfg.GoogleClientID,
		cfg.GoogleSecret,
		cfg.PublicBaseURL,
		cfg.FrontendURL,
		sessions,
		users,
		log,
	)

	handler := httpapi.New(cfg, log, google, sessions, limiter, hooks, users, visitors, pool, rdb)
	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      45 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Info("tools-api listening",
			"addr", cfg.Addr,
			"env", cfg.Env,
			"google_configured", google.Enabled(),
			"public_base_url", cfg.PublicBaseURL,
			"postgres", true,
			"valkey", true,
		)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server failed", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	log.Info("shutting down")
	if err := server.Shutdown(ctx); err != nil {
		log.Error("shutdown error", "err", err)
		os.Exit(1)
	}
}
