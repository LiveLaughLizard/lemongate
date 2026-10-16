package ui

import (
	"context"
	"log/slog"
	"net/http"

	"lemongate/internal/auth"
	"lemongate/internal/config"
	"lemongate/internal/gateway"
	"lemongate/internal/hooks"
	"lemongate/internal/limits"
	"lemongate/internal/metrics"
	"lemongate/internal/routing"
	"lemongate/internal/secret"
	"lemongate/internal/settings"
	"lemongate/internal/spend"
	"lemongate/internal/store"
)

// Deps are the core services available to every UI area.
type Deps struct {
	Cfg      *config.Config
	Store    *store.Store
	Settings *settings.Store
	Registry *routing.Registry
	Prober   *routing.Prober
	Resolver *auth.Resolver
	Limiter  *limits.Limiter
	Spend    *spend.Writer
	Gateway  *gateway.Gateway
	Box      *secret.Box
	Alerter  hooks.Alerter
	Metrics  *metrics.Endpoint
	R        *Renderer
	Features Features
}

// ReloadModels rebuilds the routing table after model/alias/credential edits.
func (d *Deps) ReloadModels(ctx context.Context) {
	if err := d.Registry.Reload(ctx); err != nil {
		slog.Error("reload models", "err", err)
	}
}

// Changed invalidates caches derived from management data (call after any mutation
// to keys, users, teams, orgs, tags, end users).
func (d *Deps) Changed() {
	d.Resolver.Invalidate()
	d.Gateway.InvalidateBudgets()
}

// Audit records an admin mutation attributed to the current principal.
func (d *Deps) Audit(r *http.Request, action, entityType, entityID, summary string, before, after any) {
	p := auth.FromContext(r.Context())
	actorID := p.UserID()
	if actorID == "" && p != nil && p.User == nil && p.IsAdmin() {
		actorID = "master"
	}
	d.Store.Audit(context.WithoutCancel(r.Context()), actorID, p.Label(), action, entityType, entityID, summary, before, after)
}
