package settingsui

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"lemongate/internal/auth"
	"lemongate/internal/metrics"
	"lemongate/internal/ui"
)

// Icons for the asset build: icon "activity" icon "key-round" icon "download" icon "shield-check" icon "lock-open" icon "refresh-cw" icon "trash-2" icon "chart-line" icon "book-open"

type metricsInfo struct {
	URL          string // full /metrics URL
	Scheme       string
	Target       string // host:port for static_configs
	AuthRequired bool
	TokenSet     bool
	TokenCreated time.Time
	EnvToken     bool
	Groups       []metricGroup
	Token        string // freshly generated token, shown once
}

type metricGroup struct {
	Name    string
	Metrics []metrics.Info
}

func (h *H) metricsInfo(ctx context.Context) metricsInfo {
	mi := metricsInfo{Scheme: "http", Target: "localhost:4000", URL: "http://localhost:4000/metrics"}
	if u, err := url.Parse(h.d.Cfg.BaseURL); err == nil && u.Host != "" {
		mi.Scheme, mi.Target = u.Scheme, u.Host
		if u.Port() == "" {
			if u.Scheme == "https" {
				mi.Target += ":443"
			} else {
				mi.Target += ":80"
			}
		}
		mi.URL = u.Scheme + "://" + u.Host + "/metrics"
	}
	if e := h.d.Metrics; e != nil {
		mi.AuthRequired = e.AuthRequired()
		mi.TokenSet = e.HasToken()
		mi.EnvToken = e.EnvToken != ""
		if mi.TokenSet {
			mi.TokenCreated = e.TokenCreated(ctx)
		}
	}
	idx := map[string]int{}
	for _, m := range metrics.Catalog {
		i, ok := idx[m.Group]
		if !ok {
			i = len(mi.Groups)
			idx[m.Group] = i
			mi.Groups = append(mi.Groups, metricGroup{Name: m.Group})
		}
		mi.Groups[i].Metrics = append(mi.Groups[i].Metrics, m)
	}
	return mi
}

func (h *H) rotateMetricsToken(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	replaced := h.d.Metrics.HasToken()
	token, err := h.d.Metrics.Rotate(r.Context())
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	summary := "Generated metrics scrape token"
	if replaced {
		summary = "Rotated metrics scrape token"
	}
	h.d.Audit(r, "update", "settings", "metrics_token", summary, nil, nil)
	pd := h.data(r.Context(), p)
	pd.Tab, pd.OOB = "metrics", true
	pd.Metrics.Token = token
	h.d.Partial(w, r, 200, area, "metrics-token-created", pd)
}

func (h *H) revokeMetricsToken(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	if err := h.d.Metrics.Revoke(r.Context()); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Audit(r, "delete", "settings", "metrics_token", "Revoked metrics scrape token", nil, nil)
	pd := h.data(r.Context(), p)
	pd.Tab = "metrics"
	ui.Toast(w, "success", "Scrape token revoked")
	h.d.Partial(w, r, 200, area, "settings-metrics", pd)
}

func (h *H) grafana(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="lemongate-grafana-dashboard.json"`)
	_, _ = w.Write(metrics.GrafanaDashboard(h.d.Settings.Current().Branding.AppName))
}
