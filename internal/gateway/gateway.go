// Package gateway implements the OpenAI-compatible data plane in front of vLLM.
package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"lemongate/internal/auth"
	"lemongate/internal/hooks"
	"lemongate/internal/limits"
	"lemongate/internal/metrics"
	"lemongate/internal/routing"
	"lemongate/internal/settings"
	"lemongate/internal/spend"
	"lemongate/internal/store"
)

const SessionCookie = "lg_session"

type Gateway struct {
	Store    *store.Store
	Resolver *auth.Resolver
	Registry *routing.Registry
	Limiter  *limits.Limiter
	Spend    *spend.Writer
	Settings *settings.Store

	// Optional extensions; nil disables them.
	Guardrails hooks.Guardrails
	Cache      hooks.Cache
	Alerter    hooks.Alerter
	// Redact masks sensitive content in stored payloads (set by the guardrails module).
	Redact func([]byte) []byte

	client *http.Client
	bc     budgetCache
}

func New(g *Gateway) *Gateway {
	g.client = &http.Client{Transport: &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:        1000,
		MaxIdleConnsPerHost: 200,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   false,
	}}
	if g.Alerter == nil {
		g.Alerter = hooks.NopAlerter
	}
	return g
}

// HTTPClient is the shared upstream client (also used by pass-through and the playground).
func (g *Gateway) HTTPClient() *http.Client { return g.client }

// Mount registers data-plane routes, both with and without the /v1 prefix.
func (g *Gateway) Mount(r chi.Router) {
	for _, prefix := range []string{"/v1", ""} {
		r.Group(func(r chi.Router) {
			r.Use(g.Authenticate)
			r.Get(prefix+"/models", g.listModels)
			r.Get(prefix+"/models/{model}", g.getModel)
			r.Post(prefix+"/chat/completions", g.handle(endpoint{route: "chat/completions", stream: true, mode: "chat"}))
			r.Post(prefix+"/completions", g.handle(endpoint{route: "completions", stream: true, mode: "completion"}))
			r.Post(prefix+"/embeddings", g.handle(endpoint{route: "embeddings", mode: "embedding"}))
			r.Post(prefix+"/rerank", g.handle(endpoint{route: "rerank", mode: "rerank"}))
			r.Post(prefix+"/score", g.handle(endpoint{route: "score", mode: "rerank"}))
			r.Post(prefix+"/responses", g.handle(endpoint{route: "responses", stream: true, mode: "chat"}))
			r.Post(prefix+"/audio/transcriptions", g.handleTranscription)
			r.Post(prefix+"/audio/translations", g.handleTranscription)
		})
	}
	r.Group(func(r chi.Router) {
		r.Use(g.Authenticate)
		r.Post("/tokenize", g.handle(endpoint{route: "tokenize", root: true, free: true}))
		r.Post("/detokenize", g.handle(endpoint{route: "detokenize", root: true, free: true}))
	})
}

// Authenticate resolves the caller from an API key, or from a browser session
// (requiring a matching CSRF header) so the admin playground can call the gateway.
func (g *Gateway) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := auth.BearerToken(r.Header)
		var p *auth.Principal
		var err error
		if token == "" {
			if c, cerr := r.Cookie(SessionCookie); cerr == nil {
				p, err = g.Resolver.ResolveSession(r.Context(), c.Value)
				if err == nil && !auth.ConstantTimeEqual(r.Header.Get("X-CSRF-Token"), p.SessionCSRF) {
					err = errors.New("missing or invalid CSRF token")
				}
			} else {
				err = auth.ErrNoCredentials
			}
		} else {
			p, err = g.Resolver.ResolveKey(r.Context(), token)
		}
		if err != nil {
			msg := err.Error()
			if errors.Is(err, auth.ErrNoCredentials) {
				msg = "Missing API key. Pass it as 'Authorization: Bearer <key>'."
			}
			WriteError(w, errAuth(msg))
			return
		}
		next.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), p)))
	})
}

type modelObj struct {
	ID          string `json:"id"`
	Object      string `json:"object"`
	Created     int64  `json:"created"`
	OwnedBy     string `json:"owned_by"`
	MaxModelLen *int   `json:"max_model_len,omitempty"`
}

func (g *Gateway) visibleModels(p *auth.Principal) []modelObj {
	allowed := p.AllowedModels(g.Registry)
	var out []modelObj
	created := time.Now().Unix()
	for _, gi := range g.Registry.Groups() {
		if allowed == nil || slices.Contains(allowed, gi.Name) {
			out = append(out, modelObj{ID: gi.Name, Object: "model", Created: created, OwnedBy: "lemongate", MaxModelLen: gi.ContextWindow})
		}
	}
	for alias, target := range g.Registry.Aliases() {
		t := g.Registry.Resolve(target)
		if g.Registry.HasGroup(t) && (allowed == nil || slices.Contains(allowed, t)) {
			out = append(out, modelObj{ID: alias, Object: "model", Created: created, OwnedBy: "lemongate"})
		}
	}
	slices.SortFunc(out, func(a, b modelObj) int { return strings.Compare(a.ID, b.ID) })
	return out
}

func (g *Gateway) listModels(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	models := g.visibleModels(p)
	if models == nil {
		models = []modelObj{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": models})
}

func (g *Gateway) getModel(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	id := chi.URLParam(r, "model")
	for _, m := range g.visibleModels(p) {
		if m.ID == id {
			writeJSON(w, http.StatusOK, m)
			return
		}
	}
	WriteError(w, errNotFound(fmt.Sprintf("The model '%s' does not exist or you do not have access to it.", id)))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func newRequestID() string { return "req_" + strings.ReplaceAll(uuid.NewString(), "-", "") }

// budgetCache holds budget data not carried on the Principal (tags, end users,
// team-member caps), refreshed periodically.
type budgetCache struct {
	mu       sync.RWMutex
	loaded   time.Time
	tags     map[string]store.Tag
	endUsers map[string]store.EndUser
	members  map[[2]string]store.TeamMember
}

func (g *Gateway) refreshBudgetCache(ctx context.Context) {
	g.bc.mu.RLock()
	fresh := time.Since(g.bc.loaded) < 15*time.Second
	g.bc.mu.RUnlock()
	if fresh {
		return
	}
	tags := map[string]store.Tag{}
	if ts, err := g.Store.ListTags(ctx); err == nil {
		for _, t := range ts {
			if t.MaxBudget != nil {
				tags[t.Name] = t
			}
		}
	}
	eus := map[string]store.EndUser{}
	if rows, err := g.Store.Pool.Query(ctx, `SELECT id, spend, max_budget, blocked FROM end_users WHERE max_budget IS NOT NULL OR blocked`); err == nil {
		for rows.Next() {
			var e store.EndUser
			if rows.Scan(&e.ID, &e.Spend, &e.MaxBudget, &e.Blocked) == nil {
				eus[e.ID] = e
			}
		}
		rows.Close()
	}
	mems := map[[2]string]store.TeamMember{}
	if rows, err := g.Store.Pool.Query(ctx, `SELECT m.team_id::text, m.user_id::text, m.spend, COALESCE(m.max_budget, t.member_max_budget)
		FROM team_members m JOIN teams t ON t.id = m.team_id WHERE m.max_budget IS NOT NULL OR t.member_max_budget IS NOT NULL`); err == nil {
		for rows.Next() {
			var m store.TeamMember
			if rows.Scan(&m.TeamID, &m.UserID, &m.Spend, &m.MaxBudget) == nil {
				mems[[2]string{m.TeamID, m.UserID}] = m
			}
		}
		rows.Close()
	}
	g.bc.mu.Lock()
	g.bc.tags, g.bc.endUsers, g.bc.members, g.bc.loaded = tags, eus, mems, time.Now()
	g.bc.mu.Unlock()
}

// InvalidateBudgets forces the next request to reload tag/end-user/member budgets.
func (g *Gateway) InvalidateBudgets() {
	g.bc.mu.Lock()
	g.bc.loaded = time.Time{}
	g.bc.mu.Unlock()
}

type budgetErr struct{ what string }

func (b budgetErr) Error() string { return "Budget exceeded for " + b.what }

func (g *Gateway) checkBudgets(ctx context.Context, p *auth.Principal, endUser string, tags []string) error {
	over := func(entity string, spent float64, max *float64) bool {
		return max != nil && spent+g.Spend.Pending(entity) >= *max
	}
	if k := p.Key; k != nil && over("key:"+k.ID, k.Spend, k.MaxBudget) {
		return budgetErr{fmt.Sprintf("key %s (spent $%.4f of $%.2f)", k.Label(), k.Spend, *k.MaxBudget)}
	}
	if u := p.User; u != nil && p.Team == nil && over("user:"+u.ID, u.Spend, u.MaxBudget) {
		return budgetErr{fmt.Sprintf("user %s", u.Email)}
	}
	if t := p.Team; t != nil && over("team:"+t.ID, t.Spend, t.MaxBudget) {
		return budgetErr{fmt.Sprintf("team %s", t.Name)}
	}
	if o := p.Org; o != nil && over("org:"+o.ID, o.Spend, o.MaxBudget) {
		return budgetErr{fmt.Sprintf("organization %s", o.Name)}
	}
	g.refreshBudgetCache(ctx)
	g.bc.mu.RLock()
	defer g.bc.mu.RUnlock()
	if p.Team != nil && p.User != nil {
		if m, ok := g.bc.members[[2]string{p.Team.ID, p.User.ID}]; ok && over("member:"+p.Team.ID+":"+p.User.ID, m.Spend, m.MaxBudget) {
			return budgetErr{fmt.Sprintf("your membership in team %s", p.Team.Name)}
		}
	}
	if endUser != "" {
		if e, ok := g.bc.endUsers[endUser]; ok {
			if e.Blocked {
				return budgetErr{"end user " + endUser + " (blocked)"}
			}
			if over("end_user:"+endUser, e.Spend, e.MaxBudget) {
				return budgetErr{"end user " + endUser}
			}
		}
	}
	for _, t := range tags {
		if tg, ok := g.bc.tags[t]; ok && over("tag:"+t, tg.Spend, tg.MaxBudget) {
			return budgetErr{"tag " + t}
		}
	}
	return nil
}

func limitSubjects(p *auth.Principal) []limits.Subject {
	var s []limits.Subject
	if k := p.Key; k != nil {
		s = append(s, limits.Subject{ID: "key:" + k.ID, Label: "API key " + k.Label(), RPM: k.RPMLimit, TPM: k.TPMLimit, MaxParallel: k.MaxParallel})
	}
	if u := p.User; u != nil {
		s = append(s, limits.Subject{ID: "user:" + u.ID, Label: "user " + u.Email, RPM: u.RPMLimit, TPM: u.TPMLimit, MaxParallel: u.MaxParallel})
	}
	if t := p.Team; t != nil {
		s = append(s, limits.Subject{ID: "team:" + t.ID, Label: "team " + t.Name, RPM: t.RPMLimit, TPM: t.TPMLimit, MaxParallel: t.MaxParallel})
	}
	if o := p.Org; o != nil {
		s = append(s, limits.Subject{ID: "org:" + o.ID, Label: "organization " + o.Name, RPM: o.RPMLimit, TPM: o.TPMLimit})
	}
	return s
}

// record finalizes metrics and hands the record to the spend writer.
func (g *Gateway) record(rec spend.Record) {
	model := rec.ModelGroup
	if model == "" {
		model = rec.Model
	}
	metrics.Requests.WithLabelValues(rec.Route, model, rec.Status).Inc()
	metrics.Latency.WithLabelValues(rec.Route, model).Observe(float64(rec.LatencyMs) / 1000)
	if rec.PromptTokens > 0 {
		metrics.Tokens.WithLabelValues(model, "prompt").Add(float64(rec.PromptTokens))
	}
	if rec.CompletionTokens > 0 {
		metrics.Tokens.WithLabelValues(model, "completion").Add(float64(rec.CompletionTokens))
	}
	if rec.Cost > 0 {
		metrics.Cost.WithLabelValues(model).Add(rec.Cost)
	}
	if rec.TTFTMs != nil {
		metrics.TTFT.WithLabelValues(model).Observe(float64(*rec.TTFTMs) / 1000)
	}
	if slow := g.Settings.Current().Alerting.SlowResponseSec; slow > 0 && rec.Status == "success" && !rec.Stream && rec.LatencyMs > slow*1000 {
		g.Alerter.Emit(hooks.Event{Kind: "slow_response", Severity: "warning", DedupeKey: "slow:" + rec.DeploymentID,
			Title:  "Slow responses from " + model,
			Body:   fmt.Sprintf("A %s request to %s (%s) took %.1fs.", rec.Route, model, rec.APIBase, float64(rec.LatencyMs)/1000),
			Fields: map[string]string{"model": model, "api_base": rec.APIBase}})
	}
	g.Spend.Submit(rec)
	if rec.Status == "error" {
		slog.Debug("request failed", "request_id", rec.RequestID, "model", model, "error", rec.Error)
	}
}

// Admit applies budget and rate-limit checks for non-model traffic (e.g. pass-through
// routes). On success the caller must invoke release when the request completes.
func (g *Gateway) Admit(ctx context.Context, p *auth.Principal, tags []string) (release func(tokens int), status int, err error) {
	if err := g.checkBudgets(ctx, p, "", tags); err != nil {
		metrics.BudgetRejected.Inc()
		return nil, http.StatusTooManyRequests, err
	}
	release, _, err = g.Limiter.Acquire(limitSubjects(p))
	if err != nil {
		var le *limits.LimitError
		if errors.As(err, &le) {
			metrics.RateLimited.WithLabelValues(le.Kind).Inc()
		}
		return nil, http.StatusTooManyRequests, err
	}
	return release, 0, nil
}
