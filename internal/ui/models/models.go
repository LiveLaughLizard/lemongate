// Package models is the model management area: model groups and their vLLM
// deployments, health, aliases, access groups and fallbacks.
package models

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"lemongate/internal/analytics"
	"lemongate/internal/auth"
	"lemongate/internal/routing"
	"lemongate/internal/store"
	"lemongate/internal/ui"
)

const area = "models"

var modes = []string{"chat", "completion", "embedding", "rerank", "classify", "audio"}

type H struct{ d *ui.Deps }

// Mount registers routes for this area on the session-protected router.
func Mount(r chi.Router, d *ui.Deps) {
	h := &H{d}
	r.Group(func(r chi.Router) {
		r.Use(ui.AdminWrites)
		r.Get("/ui/models", h.index)
		r.Get("/ui/models/table", h.table)
		r.Get("/ui/models/new", h.newForm)
		r.Post("/ui/models/test", h.testConnection)
		r.Post("/ui/models/check-all", h.checkAll)
		r.Post("/ui/models/deployments", h.create)
		r.Get("/ui/models/deployments/{id}/edit", h.editForm)
		r.Get("/ui/models/deployments/{id}/clone", h.cloneForm)
		r.Post("/ui/models/deployments/{id}", h.update)
		r.Post("/ui/models/deployments/{id}/enable", h.setEnabled(true))
		r.Post("/ui/models/deployments/{id}/disable", h.setEnabled(false))
		r.Post("/ui/models/deployments/{id}/delete", h.delete)
		r.Post("/ui/models/deployments/{id}/check", h.check)
		r.Post("/ui/models/deployments/{id}/clear-cooldown", h.clearCooldown)

		r.Get("/ui/models/aliases", h.aliases)
		r.Get("/ui/models/aliases/new", h.aliasForm)
		r.Get("/ui/models/aliases/edit", h.aliasForm)
		r.Post("/ui/models/aliases", h.saveAlias)
		r.Post("/ui/models/aliases/delete", h.deleteAlias)

		r.Get("/ui/models/access-groups", h.groups)
		r.Get("/ui/models/access-groups/new", h.groupForm)
		r.Get("/ui/models/access-groups/edit", h.groupForm)
		r.Post("/ui/models/access-groups", h.saveGroup)
		r.Post("/ui/models/access-groups/delete", h.deleteGroup)

		r.Get("/ui/models/fallbacks", h.fallbacks)
		r.Get("/ui/models/fallbacks/new", h.fallbackForm)
		r.Get("/ui/models/fallbacks/edit", h.fallbackForm)
		r.Post("/ui/models/fallbacks", h.saveFallback)
		r.Post("/ui/models/fallbacks/delete", h.deleteFallback)

		// Model group detail. Names may contain slashes, so use a catch-all.
		r.Get("/ui/models/*", h.show)
	})
}

// --- view models ---

type depView struct {
	*routing.Deployment
	Status       string // healthy | unhealthy | unknown | cooldown | disabled
	HealthError  string
	HealthAt     *time.Time
	ProbeMs      int
	LatencyMs    float64
	InFlight     int64
	MinReqs      int
	MinToks      int
	CooldownLeft int
	Req24        int64
	Fail24       int64
}

type groupView struct {
	routing.GroupInfo
	Deps      []depView
	Enabled   int
	Cooling   int
	Unhealthy int
	InFlight  int64
	MinReqs   int
	MinToks   int
	Req24     int64
	AllConfig bool
	AnyConfig bool
	Aliases   []string
	APIBases  int
	Status    string
}

func (h *H) view(d *routing.Deployment, stats map[string]store.DeploymentStat) depView {
	v := depView{Deployment: d, LatencyMs: d.LatencyMs(), InFlight: d.InFlight()}
	v.MinReqs, v.MinToks = d.MinuteUsage()
	if hl := d.Health(); hl != nil {
		t := hl.Checked
		v.HealthAt, v.ProbeMs, v.HealthError = &t, hl.LatencyMs, hl.Error
	}
	switch {
	case !d.Enabled:
		v.Status = "disabled"
	case d.CoolingDown():
		v.Status = "cooldown"
		v.CooldownLeft = int(d.CooldownRemaining().Seconds()) + 1
	case d.Health() == nil:
		v.Status = "unknown"
	case d.Health().Healthy:
		v.Status = "healthy"
	default:
		v.Status = "unhealthy"
	}
	if s, ok := stats[d.ID]; ok {
		v.Req24, v.Fail24 = s.Requests, s.Failures
	}
	return v
}

func (h *H) groupViews(ctx context.Context) []groupView {
	stats, _ := h.d.Store.DeploymentStats24h(ctx)
	aliases := h.d.Registry.Aliases()
	var out []groupView
	for _, g := range h.d.Registry.Groups() {
		gv := groupView{GroupInfo: g, AllConfig: true}
		bases := map[string]bool{}
		for _, d := range g.Deployments {
			v := h.view(d, stats)
			gv.Deps = append(gv.Deps, v)
			if d.Enabled {
				gv.Enabled++
			}
			switch v.Status {
			case "cooldown":
				gv.Cooling++
			case "unhealthy":
				gv.Unhealthy++
			}
			gv.InFlight += v.InFlight
			gv.MinReqs += v.MinReqs
			gv.MinToks += v.MinToks
			gv.Req24 += v.Req24
			gv.AllConfig = gv.AllConfig && d.FromConfig
			gv.AnyConfig = gv.AnyConfig || d.FromConfig
			bases[d.APIBase] = true
		}
		gv.APIBases = len(bases)
		for a, t := range aliases {
			if t == g.Name {
				gv.Aliases = append(gv.Aliases, a)
			}
		}
		sort.Strings(gv.Aliases)
		switch {
		case gv.Enabled == 0:
			gv.Status = "disabled"
		case g.Healthy == 0:
			gv.Status = "down"
		case g.Healthy < gv.Enabled:
			gv.Status = "degraded"
		default:
			gv.Status = "healthy"
		}
		out = append(out, gv)
	}
	return out
}

// --- index ---

type indexData struct {
	Tab         string
	CanEdit     bool
	Groups      int
	Deployments int
	Healthy     int
	Cooling     int
	Unhealthy   int
	Aliases     int
	InFlight    int64
	Strategy    string
}

func (h *H) index(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	id := indexData{Tab: r.URL.Query().Get("tab"), CanEdit: p.IsAdmin(), Strategy: h.d.Settings.Current().Routing.Strategy}
	if id.Tab == "" {
		id.Tab = "models"
	}
	for _, g := range h.groupViews(r.Context()) {
		id.Groups++
		id.Deployments += len(g.Deps)
		for _, d := range g.Deps {
			switch d.Status {
			case "healthy", "unknown":
				id.Healthy++
			case "cooldown":
				id.Cooling++
			case "unhealthy":
				id.Unhealthy++
			}
			id.InFlight += d.InFlight
		}
	}
	id.Aliases = len(h.d.Registry.Aliases())
	h.d.Render(w, r, "models/index", "models", "Models", id)
}

type tableData struct {
	Groups   []groupView
	CanEdit  bool
	Filtered bool
}

func (h *H) table(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	q := strings.ToLower(ui.FormStr(r, "q"))
	mode := ui.FormStr(r, "mode")
	status := ui.FormStr(r, "status")
	all := h.groupViews(r.Context())
	var groups []groupView
	for _, g := range all {
		if q != "" {
			hay := strings.ToLower(g.Name + " " + g.Description + " " + strings.Join(g.Tags, " ") + " " + strings.Join(g.Aliases, " "))
			for _, d := range g.Deps {
				hay += " " + strings.ToLower(d.APIBase+" "+d.UpstreamModel)
			}
			if !strings.Contains(hay, q) {
				continue
			}
		}
		if mode != "" && g.Mode != mode {
			continue
		}
		if status != "" && g.Status != status && !(status == "attention" && g.Status != "healthy") {
			continue
		}
		groups = append(groups, g)
	}
	h.d.Partial(w, r, 200, area, "models-table", tableData{Groups: groups, CanEdit: p.IsAdmin(), Filtered: q != "" || mode != "" || status != ""})
}

// --- deployment form ---

type formData struct {
	Dep         store.Deployment
	IsNew       bool
	Error       string
	Groups      []string
	Credentials []store.Credential
	Modes       []string
	Headers     string
}

func (h *H) form(ctx context.Context, d store.Deployment, isNew bool) formData {
	fd := formData{Dep: d, IsNew: isNew, Groups: h.d.Registry.AllModelNames(), Modes: modes}
	fd.Credentials, _ = h.d.Store.ListCredentials(ctx)
	var lines []string
	for k, v := range d.ExtraHeaders {
		lines = append(lines, k+": "+v)
	}
	sort.Strings(lines)
	fd.Headers = strings.Join(lines, "\n")
	return fd
}

func (h *H) newForm(w http.ResponseWriter, r *http.Request) {
	d := store.Deployment{Mode: "chat", Weight: 1, Enabled: true, TimeoutSeconds: h.d.Settings.Current().Routing.DefaultTimeoutSec}
	if g := r.URL.Query().Get("group"); g != "" {
		d.Name = g
		// Pre-fill pricing and model info from an existing deployment of the group.
		if deps := h.d.Registry.Group(g); len(deps) > 0 {
			src := deps[0].Deployment
			d.UpstreamModel, d.Mode, d.ContextWindow, d.MaxOutputTokens = src.UpstreamModel, src.Mode, src.ContextWindow, src.MaxOutputTokens
			d.InputCostPerM, d.OutputCostPerM, d.Description, d.Tags = src.InputCostPerM, src.OutputCostPerM, src.Description, src.Tags
		}
	}
	h.d.Partial(w, r, 200, area, "dep-form", h.form(r.Context(), d, true))
}

func (h *H) loadDep(w http.ResponseWriter, r *http.Request, editable bool) (*routing.Deployment, bool) {
	d := h.d.Registry.Deployment(chi.URLParam(r, "id"))
	if d == nil {
		ui.Fail(w, 404, "Deployment not found")
		return nil, false
	}
	if editable && d.FromConfig {
		ui.Fail(w, 409, "This deployment is defined in the config file and is read-only here.")
		return nil, false
	}
	return d, true
}

func (h *H) editForm(w http.ResponseWriter, r *http.Request) {
	d, ok := h.loadDep(w, r, true)
	if !ok {
		return
	}
	sd, err := h.d.Store.GetDeployment(r.Context(), d.ID)
	if err != nil {
		ui.Fail(w, 404, "Deployment not found")
		return
	}
	h.d.Partial(w, r, 200, area, "dep-form", h.form(r.Context(), sd, false))
}

// cloneForm opens a new-deployment form pre-filled from an existing one (also config ones).
func (h *H) cloneForm(w http.ResponseWriter, r *http.Request) {
	d, ok := h.loadDep(w, r, false)
	if !ok {
		return
	}
	c := d.Deployment
	c.ID, c.FromConfig, c.APIKey, c.Enabled = "", false, "", true
	h.d.Partial(w, r, 200, area, "dep-form", h.form(r.Context(), c, true))
}

var modelNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$`)

func (h *H) bind(r *http.Request, d *store.Deployment) error {
	_ = r.ParseForm()
	d.Name = ui.FormStr(r, "name")
	d.APIBase = strings.TrimRight(ui.FormStr(r, "api_base"), "/")
	d.UpstreamModel = ui.FormStr(r, "upstream_model")
	d.CredentialID = store.NullIfEmpty(ui.FormStr(r, "credential_id"))
	d.Mode = ui.FormStr(r, "mode")
	d.Weight = ui.FormInt(r, "weight", 1)
	d.RPMLimit, d.TPMLimit, d.MaxParallel = ui.FormIntPtr(r, "rpm_limit"), ui.FormIntPtr(r, "tpm_limit"), ui.FormIntPtr(r, "max_parallel")
	d.TimeoutSeconds = ui.FormInt(r, "timeout_seconds", h.d.Settings.Current().Routing.DefaultTimeoutSec)
	d.ContextWindow, d.MaxOutputTokens = ui.FormIntPtr(r, "context_window"), ui.FormIntPtr(r, "max_output_tokens")
	d.InputCostPerM, d.OutputCostPerM = ui.FormFloat(r, "input_cost_per_m"), ui.FormFloat(r, "output_cost_per_m")
	d.Description = ui.FormStr(r, "description")
	d.Tags = ui.FormList(r, "tags")
	d.ExtraHeaders = ui.FormStringMap(r, "extra_headers")
	d.Enabled = ui.FormBool(r, "enabled")
	if !modelNameRe.MatchString(d.Name) {
		return errors.New("model name is required (letters, digits and . _ : / @ + -; no spaces)")
	}
	u, err := url.Parse(d.APIBase)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("API base must be an http(s) URL, e.g. http://vllm-1:8000/v1")
	}
	if d.UpstreamModel == "" {
		d.UpstreamModel = d.Name
	}
	if !slices.Contains(modes, d.Mode) {
		return errors.New("choose a mode")
	}
	if d.Weight < 1 {
		return errors.New("weight must be at least 1")
	}
	if d.TimeoutSeconds < 1 {
		return errors.New("timeout must be at least 1 second")
	}
	if d.InputCostPerM < 0 || d.OutputCostPerM < 0 {
		return errors.New("prices cannot be negative")
	}
	for _, p := range []*int{d.RPMLimit, d.TPMLimit, d.MaxParallel, d.ContextWindow, d.MaxOutputTokens} {
		if p != nil && *p < 0 {
			return errors.New("limits cannot be negative")
		}
	}
	return nil
}

func (h *H) create(w http.ResponseWriter, r *http.Request) {
	var d store.Deployment
	if err := h.bind(r, &d); err != nil {
		fd := h.form(r.Context(), d, true)
		fd.Error = err.Error()
		h.d.Partial(w, r, 422, area, "dep-form", fd)
		return
	}
	created, err := h.d.Store.CreateDeployment(r.Context(), d)
	if err != nil {
		fd := h.form(r.Context(), d, true)
		fd.Error = err.Error()
		h.d.Partial(w, r, 422, area, "dep-form", fd)
		return
	}
	h.d.ReloadModels(r.Context())
	h.probeAsync(created.ID)
	h.d.Audit(r, "create", "deployment", created.ID, fmt.Sprintf("Added deployment %s → %s", created.Name, created.APIBase), nil, created)
	ui.Done(w, "Deployment added to "+created.Name, "refresh-models")
}

// probeAsync runs a health check in the background so new deployments get a status quickly.
func (h *H) probeAsync(id string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if d := h.d.Registry.Deployment(id); d != nil && d.Enabled {
			h.d.Prober.Check(ctx, d)
		}
	}()
}

func (h *H) update(w http.ResponseWriter, r *http.Request) {
	rd, ok := h.loadDep(w, r, true)
	if !ok {
		return
	}
	d, err := h.d.Store.GetDeployment(r.Context(), rd.ID)
	if err != nil {
		ui.Fail(w, 404, "Deployment not found")
		return
	}
	before := d
	if err := h.bind(r, &d); err != nil {
		fd := h.form(r.Context(), d, false)
		fd.Error = err.Error()
		h.d.Partial(w, r, 422, area, "dep-form", fd)
		return
	}
	if err := h.d.Store.UpdateDeployment(r.Context(), d); err != nil {
		fd := h.form(r.Context(), d, false)
		fd.Error = err.Error()
		h.d.Partial(w, r, 422, area, "dep-form", fd)
		return
	}
	h.d.ReloadModels(r.Context())
	if before.APIBase != d.APIBase || before.UpstreamModel != d.UpstreamModel || before.CredentialID != d.CredentialID {
		h.probeAsync(d.ID)
	}
	h.d.Audit(r, "update", "deployment", d.ID, fmt.Sprintf("Updated deployment %s → %s", d.Name, d.APIBase), before, d)
	ui.Done(w, "Deployment updated", "refresh-models")
}

func (h *H) setEnabled(enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d, ok := h.loadDep(w, r, true)
		if !ok {
			return
		}
		if err := h.d.Store.SetDeploymentEnabled(r.Context(), d.ID, enabled); err != nil {
			ui.Fail(w, 500, err.Error())
			return
		}
		h.d.ReloadModels(r.Context())
		verb := map[bool]string{true: "Enabled", false: "Disabled"}[enabled]
		h.d.Audit(r, strings.ToLower(verb[:len(verb)-1]), "deployment", d.ID, fmt.Sprintf("%s deployment %s → %s", verb, d.Name, d.APIBase),
			map[string]any{"enabled": !enabled}, map[string]any{"enabled": enabled})
		if enabled {
			h.probeAsync(d.ID)
		}
		ui.Toast(w, "success", verb+" "+d.Name+" @ "+hostOf(d.APIBase))
		ui.Refresh(w, "refresh-models")
		w.WriteHeader(http.StatusNoContent)
	}
}

func hostOf(base string) string {
	if u, err := url.Parse(base); err == nil && u.Host != "" {
		return u.Host
	}
	return base
}

func (h *H) delete(w http.ResponseWriter, r *http.Request) {
	d, ok := h.loadDep(w, r, true)
	if !ok {
		return
	}
	snapshot := d.Deployment
	if err := h.d.Store.DeleteDeployment(r.Context(), d.ID); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.ReloadModels(r.Context())
	h.d.Audit(r, "delete", "deployment", d.ID, fmt.Sprintf("Removed deployment %s → %s", d.Name, d.APIBase), snapshot, nil)
	if r.URL.Query().Get("from") == "detail" && !h.d.Registry.HasGroup(d.Name) {
		ui.Toast(w, "success", "Deployment removed — model group is now empty")
		ui.Redirect(w, r, "/ui/models")
		return
	}
	ui.Done(w, "Deployment removed", "refresh-models")
}

func (h *H) check(w http.ResponseWriter, r *http.Request) {
	d, ok := h.loadDep(w, r, false)
	if !ok {
		return
	}
	hl := h.d.Prober.Check(r.Context(), d)
	if hl.Healthy {
		ui.Toast(w, "success", fmt.Sprintf("%s @ %s is healthy (%d ms)", d.Name, hostOf(d.APIBase), hl.LatencyMs))
	} else {
		ui.Toast(w, "error", fmt.Sprintf("%s @ %s failed: %s", d.Name, hostOf(d.APIBase), hl.Error))
	}
	ui.Refresh(w, "refresh-models")
	w.WriteHeader(http.StatusNoContent)
}

func (h *H) checkAll(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	h.d.Prober.CheckAll(ctx)
	total, healthy := 0, 0
	for _, d := range h.d.Registry.AllDeployments() {
		if !d.Enabled {
			continue
		}
		total++
		if hl := d.Health(); hl != nil && hl.Healthy {
			healthy++
		}
	}
	kind := "success"
	if healthy < total {
		kind = "warning"
	}
	ui.Toast(w, kind, fmt.Sprintf("Health check complete: %d of %d deployments healthy", healthy, total))
	ui.Refresh(w, "refresh-models")
	w.WriteHeader(http.StatusNoContent)
}

func (h *H) clearCooldown(w http.ResponseWriter, r *http.Request) {
	d, ok := h.loadDep(w, r, false)
	if !ok {
		return
	}
	d.ClearCooldown()
	h.d.Audit(r, "clear_cooldown", "deployment", d.ID, fmt.Sprintf("Cleared cooldown of %s → %s", d.Name, d.APIBase), nil, nil)
	ui.Toast(w, "success", "Cooldown cleared — "+d.Name+" @ "+hostOf(d.APIBase)+" receives traffic again")
	ui.Refresh(w, "refresh-models")
	w.WriteHeader(http.StatusNoContent)
}

// --- test connection ---

type testData struct {
	OK        bool
	Error     string
	Models    []string
	LatencyMs int64
	URL       string
	Current   string
}

func (h *H) testConnection(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	base := ui.FormStr(r, "api_base")
	td := testData{Current: ui.FormStr(r, "upstream_model")}
	u, err := url.Parse(base)
	if base == "" || err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		td.Error = "Enter an http(s) API base first."
		h.d.Partial(w, r, 200, area, "test-result", td)
		return
	}
	apiKey := ""
	if cid := ui.FormStr(r, "credential_id"); cid != "" {
		if c, err := h.d.Store.GetCredential(r.Context(), cid); err == nil {
			apiKey, _ = h.d.Box.OpenString(c.SecretEnc)
		}
	} else if id := ui.FormStr(r, "id"); id != "" {
		if d := h.d.Registry.Deployment(id); d != nil {
			apiKey = d.APIKey
		}
	}
	td.URL = routing.V1Base(base) + "/models"
	start := time.Now()
	td.Models, err = listUpstreamModels(r.Context(), td.URL, apiKey)
	td.LatencyMs = time.Since(start).Milliseconds()
	if err != nil {
		td.Error = err.Error()
	} else {
		td.OK = true
	}
	h.d.Partial(w, r, 200, area, "test-result", td)
}

var testClient = &http.Client{Timeout: 8 * time.Second}

func listUpstreamModels(ctx context.Context, u, apiKey string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := testClient.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("could not reach the server: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("the server rejected the credentials (HTTP %d)", resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("GET /v1/models returned HTTP %d", resp.StatusCode)
	}
	var lm struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &lm); err != nil {
		return nil, errors.New("the response is not an OpenAI-compatible model list")
	}
	var out []string
	for _, m := range lm.Data {
		out = append(out, m.ID)
	}
	return out, nil
}

// --- group detail ---

type checkStrip struct {
	Dep       depView
	Checks    []store.HealthCheck  // oldest → newest
	Slots     []*store.HealthCheck // fixed-width strip, nil = no data
	Uptime    float64
	AvgMs     float64
	LastError string
	Chart     analytics.ChartSpec
}

type showData struct {
	Group        groupView
	CanEdit      bool
	Days         int
	Totals       analytics.Totals
	Chart        analytics.ChartSpec
	ReqChart     analytics.ChartSpec
	TopKeys      []analytics.Row
	Health       []checkStrip
	AccessGroups []string
	Fallbacks    []string
	CtxFallbacks []string
	FallbackFor  []string
	Strategy     string
}

func (h *H) show(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	name, _ := url.PathUnescape(chi.URLParam(r, "*"))
	var gv *groupView
	for _, g := range h.groupViews(r.Context()) {
		if g.Name == name {
			g := g
			gv = &g
			break
		}
	}
	if gv == nil {
		if target := h.d.Registry.Resolve(name); target != name && h.d.Registry.HasGroup(target) {
			http.Redirect(w, r, "/ui/models/"+target, http.StatusFound)
			return
		}
		http.NotFound(w, r)
		return
	}
	days := ui.FormInt(r, "days", 30)
	if days <= 0 || days > 365 {
		days = 30
	}
	f := analytics.LastDays(days)
	f.Model = name
	sd := showData{Group: *gv, CanEdit: p.IsAdmin(), Days: days, Strategy: h.d.Settings.Current().Routing.Strategy}
	sd.Totals, _ = analytics.GetTotals(r.Context(), h.d.Store.Pool, f)
	pts, _ := analytics.Daily(r.Context(), h.d.Store.Pool, f)
	sd.Chart = analytics.DailyChart(pts, "bar", "money", map[string]func(analytics.DayPoint) float64{
		"Spend": func(p analytics.DayPoint) float64 { return p.Cost },
	}, "Spend")
	sd.ReqChart = analytics.DailyChart(pts, "line", "num", map[string]func(analytics.DayPoint) float64{
		"Requests": func(p analytics.DayPoint) float64 { return float64(p.Requests) },
		"Failures": func(p analytics.DayPoint) float64 { return float64(p.Failures) },
	}, "Requests", "Failures")
	sd.TopKeys, _ = analytics.Breakdown(r.Context(), h.d.Store.Pool, f, "key", 6)

	for _, d := range gv.Deps {
		cs := checkStrip{Dep: d}
		if !d.FromConfig {
			checks, _ := h.d.Store.HealthHistory(r.Context(), []string{d.ID}, 48)
			slices.Reverse(checks)
			cs.Checks = checks
			ok, lat := 0, 0
			chart := analytics.ChartSpec{Type: "line", Format: "ms", Datasets: []analytics.Dataset{{Label: "Probe latency"}}}
			for _, c := range checks {
				if c.OK {
					ok++
					lat += c.LatencyMs
				} else {
					cs.LastError = c.Error
				}
				chart.Labels = append(chart.Labels, c.CheckedAt.Local().Format("Jan 2 15:04"))
				chart.Datasets[0].Data = append(chart.Datasets[0].Data, float64(c.LatencyMs))
			}
			cs.Slots = make([]*store.HealthCheck, 48)
			for i := range checks {
				cs.Slots[48-len(checks)+i] = &checks[i]
			}
			if len(checks) > 0 {
				cs.Uptime = float64(ok) / float64(len(checks)) * 100
			}
			if ok > 0 {
				cs.AvgMs = float64(lat) / float64(ok)
			}
			no := false
			chart.Legend = &no
			cs.Chart = chart
		}
		sd.Health = append(sd.Health, cs)
	}

	ags, _ := h.d.Store.ListAccessGroups(r.Context())
	seen := map[string]bool{}
	for _, g := range ags {
		if slices.Contains(g.Models, name) {
			sd.AccessGroups = append(sd.AccessGroups, g.Name)
			seen[g.Name] = true
		}
	}
	for g, models := range h.d.Cfg.File.AccessGroups {
		if slices.Contains(models, name) && !seen[g] {
			sd.AccessGroups = append(sd.AccessGroups, g)
		}
	}
	sort.Strings(sd.AccessGroups)
	sd.Fallbacks = h.d.Registry.Fallbacks(name, false)
	sd.CtxFallbacks = h.d.Registry.Fallbacks(name, true)
	for _, m := range h.d.Registry.AllModelNames() {
		if slices.Contains(h.d.Registry.Fallbacks(m, false), name) || slices.Contains(h.d.Registry.Fallbacks(m, true), name) {
			sd.FallbackFor = append(sd.FallbackFor, m)
		}
	}
	if r.Header.Get("HX-Target") == "model-detail" {
		h.d.Partial(w, r, 200, area, "model-detail", sd)
		return
	}
	h.d.Render(w, r, "models/show", "models", name, sd, ui.Crumb{Label: "Models", Href: "/ui/models"})
}
