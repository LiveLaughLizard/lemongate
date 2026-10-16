// Package settingsui edits runtime settings (routing, logging, cache, alerting,
// branding, general) and shows read-only environment information.
package settingsui

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"lemongate/internal/auth"
	"lemongate/internal/settings"
	"lemongate/internal/store"
	"lemongate/internal/ui"
)

const area = "settings"

var sections = []string{"general", "routing", "logging", "cache", "alerting", "branding", "metrics"}

type H struct{ d *ui.Deps }

// Mount registers routes for this area on the session-protected router.
func Mount(r chi.Router, d *ui.Deps) {
	h := &H{d}
	r.Group(func(r chi.Router) {
		r.Use(ui.AdminWrites)
		r.Get("/ui/settings", h.index)
		r.Post("/ui/settings/{section}", h.save)
		r.Post("/ui/settings/metrics/token", h.rotateMetricsToken)
		r.Post("/ui/settings/metrics/token/revoke", h.revokeMetricsToken)
		r.Get("/ui/settings/metrics/grafana.json", h.grafana)
	})
}

type Env struct {
	BaseURL      string
	Listen       string
	ConfigPath   string
	Version      string
	GoVersion    string
	DevMode      bool
	DBConnected  bool
	DBLatencyMs  int64
	SSO          bool
	SSOIssuer    string
	SMTP         bool
	SMTPHost     string
	SecretKeySet bool
	FileModels   int
	SessionHours int
	Deployments  int
	ModelGroups  int
}

// Strategy icons for the asset build: icon "shuffle" icon "activity" icon "timer" icon "gauge"
type Strategy struct{ Value, Label, Help, Icon string }

var strategies = []Strategy{
	{"weighted", "Weighted random", "Spreads traffic randomly in proportion to each deployment's weight. Predictable and cheap — the right default.", "shuffle"},
	{"least_busy", "Least busy", "Sends each request to the deployment with the fewest in-flight requests. Good when request sizes vary a lot.", "activity"},
	{"latency", "Lowest latency", "Prefers the deployment with the lowest recent (EWMA) response time. Unmeasured deployments are sampled first.", "timer"},
	{"usage", "Usage based", "Picks the deployment that has served the fewest tokens this minute. Keeps replicas evenly loaded under TPM caps.", "gauge"},
}

type pageData struct {
	S          settings.Settings
	Tab        string
	Env        Env
	Overrides  map[string]map[string]bool
	Strategies []Strategy
	CanEdit    bool
	Error      string
	Section    string // section the error belongs to
	Thresholds string
	Metrics    metricsInfo
	OOB        bool // render the metrics section as an out-of-band swap
}

func (h *H) data(ctx context.Context, p *auth.Principal) pageData {
	s := h.d.Settings.Current()
	pd := pageData{S: s, Tab: "general", Env: h.env(ctx), Overrides: h.overrides(), Strategies: strategies, CanEdit: p.IsAdmin()}
	var th []string
	for _, t := range s.Alerting.BudgetThresholds {
		th = append(th, strconv.Itoa(t))
	}
	pd.Thresholds = strings.Join(th, ", ")
	pd.Metrics = h.metricsInfo(ctx)
	return pd
}

func (h *H) overrides() map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for sec, v := range h.d.Cfg.File.Settings {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		out[sec] = map[string]bool{}
		for k := range m {
			out[sec][k] = true
		}
	}
	return out
}

func (h *H) env(ctx context.Context) Env {
	c := h.d.Cfg
	e := Env{BaseURL: c.BaseURL, Listen: c.Listen, ConfigPath: c.ConfigPath, Version: h.d.R.Version, GoVersion: runtime.Version(),
		DevMode: c.DevMode, SSO: h.d.Features.SSO, SMTP: h.d.Features.SMTP, SecretKeySet: c.SecretKey != "",
		FileModels: len(c.File.Models), SessionHours: c.SessionHours}
	if e.SSO {
		e.SSOIssuer = hostOnly(c.OIDC.Issuer)
	}
	if e.SMTP {
		e.SMTPHost = c.SMTP.Host
	}
	start := time.Now()
	pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	e.DBConnected = h.d.Store.Pool.Ping(pctx) == nil
	e.DBLatencyMs = time.Since(start).Milliseconds()
	groups := h.d.Registry.Groups()
	e.ModelGroups = len(groups)
	for _, g := range groups {
		e.Deployments += len(g.Deployments)
	}
	return e
}

// hostOnly keeps scheme://host of a URL (no credentials, no path).
func hostOnly(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func (h *H) index(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	pd := h.data(r.Context(), p)
	if t := r.URL.Query().Get("tab"); t != "" {
		pd.Tab = t
	}
	h.d.Render(w, r, "settings/index", "settings", "Settings", pd)
}

func (h *H) save(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	section := chi.URLParam(r, "section")
	valid := false
	for _, s := range sections {
		valid = valid || s == section
	}
	if !valid {
		ui.Fail(w, 404, "Unknown settings section")
		return
	}
	_ = r.ParseForm()
	before := h.d.Settings.Current()
	next := before
	if err := bind(r, section, &next); err != nil {
		pd := h.data(r.Context(), p)
		pd.S, pd.Error, pd.Section, pd.Tab = next, err.Error(), section, section
		h.d.Partial(w, r, 422, area, "settings-"+section, pd)
		return
	}
	saved, err := h.d.Settings.Update(r.Context(), func(s *settings.Settings) { *s = next })
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Audit(r, "update", "settings", section, "Updated "+section+" settings", sectionOf(before, section), sectionOf(saved, section))
	pd := h.data(r.Context(), p)
	pd.Tab = section
	ui.Toast(w, "success", strings.ToUpper(section[:1])+section[1:]+" settings saved")
	h.d.Partial(w, r, 200, area, "settings-"+section, pd)
}

func sectionOf(s settings.Settings, section string) any {
	switch section {
	case "general":
		return s.General
	case "routing":
		return s.Routing
	case "logging":
		return s.Logging
	case "cache":
		return s.Cache
	case "alerting":
		return s.Alerting
	case "branding":
		return s.Branding
	case "metrics":
		return s.Metrics
	}
	return nil
}

func intIn(r *http.Request, k, label string, min, max int) (int, error) {
	v := ui.FormStr(r, k)
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, errors.New(label + " must be a whole number")
	}
	if n < min || n > max {
		return 0, errors.New(label + " must be between " + strconv.Itoa(min) + " and " + strconv.Itoa(max))
	}
	return n, nil
}

func bind(r *http.Request, section string, s *settings.Settings) error {
	var err error
	must := func(n int, e error) int {
		if e != nil && err == nil {
			err = e
		}
		return n
	}
	switch section {
	case "general":
		g := &s.General
		g.DefaultKeyBudget = ui.FormFloatPtr(r, "default_key_budget")
		if g.DefaultKeyBudget != nil && *g.DefaultKeyBudget < 0 {
			return errors.New("default key budget cannot be negative")
		}
		g.DefaultKeyDuration = ui.FormStr(r, "default_key_duration")
		if g.DefaultKeyDuration != "" {
			if _, ok := store.ParseDuration(g.DefaultKeyDuration); !ok {
				return errors.New(`default key lifetime must be a duration like "30d" or "12h"`)
			}
		}
		g.AllowMemberKeys = ui.FormBool(r, "allow_member_keys")
		g.TrackEndUsers = ui.FormBool(r, "track_end_users")
		g.MaxRequestBytes = must(intIn(r, "max_request_mb", "Max request size", 1, 1024)) << 20
	case "routing":
		rt := &s.Routing
		rt.Strategy = ui.FormStr(r, "strategy")
		ok := false
		for _, st := range strategies {
			ok = ok || st.Value == rt.Strategy
		}
		if !ok {
			return errors.New("choose a routing strategy")
		}
		rt.NumRetries = must(intIn(r, "num_retries", "Retries", 0, 10))
		rt.RetryBackoffMs = must(intIn(r, "retry_backoff_ms", "Retry backoff", 0, 60000))
		rt.DefaultTimeoutSec = must(intIn(r, "default_timeout_sec", "Default timeout", 1, 86400))
		rt.CooldownFailures = must(intIn(r, "cooldown_failures", "Cooldown failures", 0, 1000))
		rt.CooldownSeconds = must(intIn(r, "cooldown_seconds", "Cooldown duration", 0, 86400))
		rt.HealthCheckSec = must(intIn(r, "health_check_sec", "Health check interval", 0, 86400))
		a := ui.FormFloat(r, "latency_ewma_alpha")
		if a <= 0 || a > 1 {
			return errors.New("latency smoothing must be between 0 (exclusive) and 1")
		}
		rt.LatencyEWMAAlpha = a
	case "logging":
		l := &s.Logging
		l.StorePayloads = ui.FormBool(r, "store_payloads")
		l.RedactPayloads = ui.FormBool(r, "redact_payloads")
		l.RetentionDays = must(intIn(r, "retention_days", "Retention", 0, 3650))
		l.MaxPayloadBytes = must(intIn(r, "max_payload_kb", "Max payload size", 1, 16384)) << 10
	case "cache":
		c := &s.Cache
		c.Enabled = ui.FormBool(r, "enabled")
		c.PerKey = ui.FormBool(r, "per_key")
		c.TTLSeconds = must(intIn(r, "ttl_seconds", "TTL", 1, 30*86400))
		c.MaxEntries = must(intIn(r, "max_entries", "Max entries", 1, 10_000_000))
	case "alerting":
		a := &s.Alerting
		var th []int
		for _, p := range ui.FormList(r, "budget_thresholds") {
			n, e := strconv.Atoi(strings.TrimSuffix(p, "%"))
			if e != nil || n <= 0 || n > 1000 {
				return errors.New("budget thresholds must be percentages like 50, 80, 100")
			}
			th = append(th, n)
		}
		a.BudgetThresholds = th
		a.ErrorRatePercent = must(intIn(r, "error_rate_percent", "Error rate threshold", 0, 100))
		a.SlowResponseSec = must(intIn(r, "slow_response_sec", "Slow response threshold", 0, 86400))
		a.DedupeMinutes = must(intIn(r, "dedupe_minutes", "Dedupe window", 0, 10080))
		a.DailyReport = ui.FormBool(r, "daily_report")
		a.DailyReportHourUTC = must(intIn(r, "daily_report_hour_utc", "Report hour", 0, 23))
		a.KeyExpiryDays = must(intIn(r, "key_expiry_days", "Key expiry warning", 0, 365))
	case "metrics":
		m := &s.Metrics
		m.Enabled = ui.FormBool(r, "enabled")
		m.RequireAuth = ui.FormBool(r, "require_auth")
		m.EntityMetrics = ui.FormBool(r, "entity_metrics")
	case "branding":
		b := &s.Branding
		b.AppName = ui.FormStr(r, "app_name")
		b.Tagline = ui.FormStr(r, "tagline")
		b.LogoURL = ui.FormStr(r, "logo_url")
		if b.AppName == "" {
			return errors.New("app name is required")
		}
		if len(b.AppName) > 40 || len(b.Tagline) > 80 {
			return errors.New("app name (max 40) or tagline (max 80) is too long")
		}
		if b.LogoURL != "" && !strings.HasPrefix(b.LogoURL, "https://") && !strings.HasPrefix(b.LogoURL, "http://") && !strings.HasPrefix(b.LogoURL, "/") {
			return errors.New("logo URL must be an http(s) URL or a path starting with /")
		}
	}
	return err
}
