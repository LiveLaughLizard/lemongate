// Command lemongate runs the gateway and admin console.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"lemongate/internal/app"
	"lemongate/internal/auth"
	"lemongate/internal/config"
	"lemongate/internal/db"
)

func main() {
	level := slog.LevelInfo
	if os.Getenv("LEMONGATE_DEBUG") == "1" {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve()
	case "migrate":
		err = migrate()
	case "new-key":
		plain, hash, _ := auth.NewKey()
		fmt.Printf("key:  %s\nhash: %s\n", plain, hash)
	case "version":
		fmt.Println(app.Version)
	default:
		fmt.Fprintf(os.Stderr, "usage: lemongate [serve|migrate|new-key|version]\n")
		os.Exit(2)
	}
	if err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func migrate() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	return db.Migrate(ctx, pool)
}

func serve() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a, err := app.New(ctx, cfg)
	if err != nil {
		return err
	}
	defer a.Close()
	bgCtx, cancelBg := context.WithCancel(context.Background())
	wait := a.Run(bgCtx)

	srv := &http.Server{Addr: cfg.Listen, Handler: a.Handler(), ReadHeaderTimeout: 15 * time.Second}
	errc := make(chan error, 1)
	go func() {
		slog.Info("LemonGate listening", "addr", cfg.Listen, "version", app.Version, "ui", cfg.BaseURL+"/ui")
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		cancelBg()
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		slog.Info("shutting down")
		shCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = srv.Shutdown(shCtx)
		cancelBg()
	}
	wait()
	return nil
}
