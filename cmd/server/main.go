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
	"github.com/riyanathariq/tools-api.riyanathariq.space/internal/httpapi"
)

func main() {
	_ = godotenv.Load()

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load()
	if err != nil {
		log.Error("invalid config", "err", err)
		os.Exit(1)
	}

	sessions := auth.NewSessionManager(cfg.SessionSecret, cfg.CookieName, cfg.CookieSecure, cfg.SessionTTL)
	google := auth.NewGoogleAuth(
		cfg.GoogleClientID,
		cfg.GoogleSecret,
		cfg.PublicBaseURL,
		cfg.FrontendURL,
		sessions,
		log,
	)

	handler := httpapi.New(cfg, log, google)
	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Info("tools-api listening",
			"addr", cfg.Addr,
			"env", cfg.Env,
			"google_configured", google.Enabled(),
			"public_base_url", cfg.PublicBaseURL,
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
