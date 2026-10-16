// Package app assembles every component into a running server.
package app

import (
	"context"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"lemongate/internal/alerting"
	"lemongate/internal/api"
	"lemongate/internal/auth"
	"lemongate/internal/cache"
	"lemongate/internal/config"
	"lemongate/internal/db"
	"lemongate/internal/gateway"
	"lemongate/internal/guardrails"
	"lemongate/internal/limits"
	"lemongate/internal/mcpgw"
	"lemongate/internal/metrics"
	"lemongate/internal/passthrough"
	"lemongate/internal/routing"
	"lemongate/internal/secret"
	"lemongate/internal/settings"
	"lemongate/internal/spend"
	"lemongate/internal/store"
	"lemongate/internal/ui"
	"lemongate/internal/ui/alertsui"
	"lemongate/internal/ui/audit"
	"lemongate/internal/ui/budgets"
	"lemongate/internal/ui/cacheui"
	"lemongate/internal/ui/credentials"
	"lemongate/internal/ui/dashboard"
	"lemongate/internal/ui/endusers"
	"lemongate/internal/ui/guardrailsui"
	"lemongate/internal/ui/hub"
	"lemongate/internal/ui/keys"
	"lemongate/internal/ui/logs"
	"lemongate/internal/ui/mcpui"
	"lemongate/internal/ui/models"
	"lemongate/internal/ui/orgs"
	"lemongate/internal/ui/passthroughui"
	"lemongate/internal/ui/playground"
	"lemongate/internal/ui/session"
	"lemongate/internal/ui/settingsui"
	"lemongate/internal/ui/sso"
	"lemongate/internal/ui/tags"
	"lemongate/internal/ui/teams"
	"lemongate/internal/ui/usage"
	"lemongate/internal/ui/users"
	"lemongate/web"
)

var Version = "dev"

type App struct {
	Cfg      *config.Config
	Pool     *pgxpool.Pool
	Store    *store.Store
	Settings *settings.Store
	Box      *secret.Box
	Resolver *auth.Resolver
	Registry *routing.Registry
	Prober   *routing.Prober
	Limiter  *limits.Limiter
	Spend    *spend.Writer
	Gateway  *gateway.Gateway

	Guardrails  *guardrails.Engine
	Cache       *cache.Cache
	Passthrough *passthrough.Router
	MCP         *mcpgw.Gateway
	Alerter     *alerting.Alerter
	Metrics     *metrics.Endpoint

	UI     *ui.Deps
	assets fs.FS
}

func New(ctx context.Context, cfg *config.Config) (*App, error) {
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	if err := db.Migrate(ctx, pool); err != nil {
		return nil, err
	}
	if err := revokeStaleMasterSessions(ctx, pool, cfg.MasterKey); err != nil {
		return nil, err
	}
	box, err := secret.New(cfg.SecretKey)
	if err != nil {
		return nil, err
	}
	a := &App{Cfg: cfg, Pool: pool, Box: box, Store: store.New(pool), Settings: settings.NewStore(pool)}
	if err := a.Settings.Load(ctx, cfg.File.Settings); err != nil {
		return nil, err
	}
	a.Resolver = auth.NewResolver(a.Store, cfg.MasterKey)
	a.Registry = routing.NewRegistry(a.Store, box, cfg.File, a.Settings)
	if err := a.Registry.Reload(ctx); err != nil {
		return nil, err
	}
	a.Limiter = limits.New()
	a.Spend = spend.NewWriter(pool)
	a.Spend.AfterFlush(a.Resolver.Invalidate)

	a.Alerter = alerting.New(pool, box, a.Settings, cfg.SMTP)
	a.Prober = routing.NewProber(a.Registry, a.Alerter)
	a.Prober.OnCheck = func(d *routing.Deployment, h routing.Health) {
		if !d.FromConfig {
			_, _ = pool.Exec(context.Background(), `INSERT INTO health_checks (deployment_id, ok, latency_ms, error) VALUES ($1,$2,$3,$4)`,
				d.ID, h.Healthy, h.LatencyMs, h.Error)
		}
	}

	a.Gateway = gateway.New(&gateway.Gateway{Store: a.Store, Resolver: a.Resolver, Registry: a.Registry, Limiter: a.Limiter,
		Spend: a.Spend, Settings: a.Settings, Alerter: a.Alerter})
	a.Guardrails = guardrails.New(pool, a.Settings, a.Gateway.HTTPClient(), a.Registry)
	if err := a.Guardrails.Reload(ctx); err != nil {
		slog.Warn("load guardrails", "err", err)
	}
	a.Gateway.Guardrails = a.Guardrails
	a.Gateway.Redact = a.Guardrails.Redact
	a.Cache = cache.New(a.Settings)
	a.Gateway.Cache = a.Cache
	a.Passthrough = passthrough.New(a.Store, box, a.Gateway.HTTPClient(), a.Resolver, a.Spend)
	a.Passthrough.Admit = a.Gateway.Admit
	if err := a.Passthrough.Reload(ctx); err != nil {
		slog.Warn("load pass-through routes", "err", err)
	}
	a.MCP = mcpgw.New(a.Store, box, a.Resolver)
	if err := a.MCP.Reload(ctx); err != nil {
		slog.Warn("load MCP servers", "err", err)
	}
	a.Alerter.Watch(a.Spend)

	a.Metrics = metrics.NewEndpoint(pool, a.Settings, cfg.MasterKey, cfg.MetricsToken)
	if err := a.Metrics.Load(ctx); err != nil {
		slog.Warn("load metrics token", "err", err)
	}
	metrics.BuildInfo.Reset()
	metrics.BuildInfo.WithLabelValues(Version, runtime.Version()).Set(1)
	metrics.SetLive(&liveCollector{a: a})
	api.SetHooks(api.Hooks{ReloadGuardrails: a.Guardrails.Reload, ReloadMCP: a.MCP.Reload, ReloadPassthrough: a.Passthrough.Reload, Guardrails: a.Guardrails})

	assetDir := ""
	if cfg.DevMode {
		assetDir = "web"
	}
	a.assets = web.FS(assetDir)
	r := ui.NewRenderer(a.assets, cfg.DevMode)
	r.Version = Version
	a.UI = &ui.Deps{Cfg: cfg, Store: a.Store, Settings: a.Settings, Registry: a.Registry, Prober: a.Prober,
		Resolver: a.Resolver, Limiter: a.Limiter, Spend: a.Spend, Gateway: a.Gateway, Box: box, Alerter: a.Alerter, Metrics: a.Metrics, R: r}
	return a, nil
}

func (a *App) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RealIP, middleware.Recoverer, requestLogger, securityHeaders(strings.HasPrefix(a.Cfg.BaseURL, "https://")))

	r.Get("/", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/ui", http.StatusFound) })
	r.Handle("/static/*", http.StripPrefix("/static", staticHandler(a.assets, a.Cfg.DevMode)))
	r.Get("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/static/img/favicon.svg", http.StatusMovedPermanently)
	})
	r.Get("/health/live", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"status":"ok"}`)) })
	r.Get("/health/ready", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := a.Pool.Ping(ctx); err != nil {
			http.Error(w, `{"status":"unavailable","database":"down"}`, http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok","database":"up"}`))
	})
	r.Handle("/metrics", a.Metrics)

	a.Gateway.Mount(r)
	a.Passthrough.Mount(r)
	a.MCP.Mount(r)
	api.Mount(r, a.UI)

	d := a.UI
	session.Mount(r, d)
	d.Features.SSO = sso.Mount(r, d)
	d.Features.SSOLabel = a.Cfg.OIDC.ButtonLabel
	d.Features.SMTP = a.Cfg.SMTP.Enabled()
	r.Group(func(r chi.Router) {
		r.Use(d.RequireSession)
		dashboard.Mount(r, d)
		playground.Mount(r, d)
		hub.Mount(r, d)
		usage.Mount(r, d)
		logs.Mount(r, d)
		keys.Mount(r, d)
		models.Mount(r, d)
		credentials.Mount(r, d)
		teams.Mount(r, d)
		orgs.Mount(r, d)
		users.Mount(r, d)
		endusers.Mount(r, d)
		budgets.Mount(r, d)
		tags.Mount(r, d)
		settingsui.Mount(r, d)
		audit.Mount(r, d)
		guardrailsui.Mount(r, d, a.Guardrails)
		cacheui.Mount(r, d, a.Cache)
		passthroughui.Mount(r, d, a.Passthrough)
		mcpui.Mount(r, d, a.MCP)
		alertsui.Mount(r, d, a.Alerter)
	})
	return r
}

// Run starts background workers; it returns when ctx is cancelled and the
// spend writer has drained.
func (a *App) Run(ctx context.Context) (wait func()) {
	done := make(chan struct{})
	go func() { a.Spend.Run(ctx); close(done) }()
	go a.Prober.Run(ctx)
	go a.Alerter.Run(ctx)
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		hourly := time.Now()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				a.Limiter.GC()
				if n, err := spend.ResetBudgets(ctx, a.Pool); err != nil {
					slog.Error("budget reset", "err", err)
				} else if n > 0 {
					slog.Info("budgets reset", "count", n)
					a.Resolver.Invalidate()
					a.Gateway.InvalidateBudgets()
				}
				if time.Since(hourly) > time.Hour {
					hourly = time.Now()
					spend.PurgeOld(ctx, a.Pool, a.Settings.Current().Logging.RetentionDays)
				}
			}
		}
	}()
	return func() { <-done }
}

func (a *App) Close() {
	a.MCP.Close()
	a.Pool.Close()
}

// staticHandler serves files under static/ only (never templates), without directory listings.
func staticHandler(assets fs.FS, dev bool) http.Handler {
	sub, err := fs.Sub(assets, "static")
	if err != nil {
		panic(err)
	}
	fsrv := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if st, err := fs.Stat(sub, name); err != nil || st.IsDir() {
			http.NotFound(w, r)
			return
		}
		if dev {
			w.Header().Set("Cache-Control", "no-cache")
		} else {
			w.Header().Set("Cache-Control", "public, max-age=86400")
		}
		fsrv.ServeHTTP(w, r)
	})
}

// securityHeaders sets browser hardening headers on every response. Pass-through
// routes add a sandbox CSP of their own (see package passthrough).
func securityHeaders(https bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "same-origin")
			h.Set("Content-Security-Policy", "frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'")
			if https {
				h.Set("Strict-Transport-Security", "max-age=31536000")
			}
			next.ServeHTTP(w, r)
		})
	}
}

func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		if len(r.URL.Path) > 7 && r.URL.Path[:8] == "/static/" {
			return
		}
		slog.Debug("http", "method", r.Method, "path", r.URL.Path, "status", ww.Status(), "dur", time.Since(start))
	})
}
