// Package keys is the API key management area: list, create, edit, rotate, block, delete.
// It is also the reference pattern for other console areas.
package keys

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"lemongate/internal/analytics"
	"lemongate/internal/auth"
	"lemongate/internal/store"
	"lemongate/internal/ui"
)

const area = "keys"

type H struct{ d *ui.Deps }

func Mount(r chi.Router, d *ui.Deps) {
	h := &H{d}
	r.Get("/ui/keys", h.index)
	r.Get("/ui/keys/table", h.table)
	r.Get("/ui/keys/new", h.newForm)
	r.Post("/ui/keys", h.create)
	r.Get("/ui/keys/{id}", h.show)
	r.Get("/ui/keys/{id}/edit", h.editForm)
	r.Post("/ui/keys/{id}", h.update)
	r.Post("/ui/keys/{id}/regenerate", h.regenerate)
	r.Post("/ui/keys/{id}/block", h.setBlocked(true))
	r.Post("/ui/keys/{id}/unblock", h.setBlocked(false))
	r.Post("/ui/keys/{id}/reset-spend", h.resetSpend)
	r.Post("/ui/keys/{id}/delete", h.delete)
	r.Post("/ui/keys/{id}/restore", h.restore)
	r.Post("/ui/keys/{id}/purge", h.purge)
}

// --- listing ---

type indexData struct {
	Teams     []store.Team
	CanCreate bool
	Deleted   bool
}

func (h *H) index(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	teams := h.visibleTeams(r.Context(), p)
	h.d.Render(w, r, "keys/index", "keys", "API keys", indexData{Teams: teams, CanCreate: h.canCreateAny(p), Deleted: r.URL.Query().Get("deleted") == "1"})
}

type tableData struct {
	Keys    []store.Key
	Deleted bool
	Usage   map[string]liveUsage
}

type liveUsage struct {
	RPM      float64
	InFlight int
}

func (h *H) table(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	q := r.URL.Query()
	f := store.KeyFilter{Search: q.Get("q"), TeamID: q.Get("team"), Deleted: q.Get("deleted") == "1"}
	keys, err := h.d.Store.ListKeys(r.Context(), f)
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	if !p.CanViewAll() {
		keys = slices.DeleteFunc(keys, func(k store.Key) bool { return !p.CanViewKey(k) })
	}
	usage := map[string]liveUsage{}
	for _, k := range keys {
		rpm, _, inflight := h.d.Limiter.Usage("key:" + k.ID)
		usage[k.ID] = liveUsage{RPM: rpm, InFlight: inflight}
	}
	h.d.Partial(w, r, 200, area, "keys-table", tableData{Keys: keys, Deleted: f.Deleted, Usage: usage})
}

// --- create / edit form ---

type formData struct {
	Key          store.Key
	IsNew        bool
	Error        string
	Users        []store.User
	Teams        []store.Team
	Models       []string
	AccessGroups []string
	Guardrails   []string
	Policies     []string
	MCPServers   []string
	ExpiresIn    string
	CanSetOwner  bool
	CanSetScope  bool
}

// SelectedModels merges models and "group:"-prefixed access groups for the picker.
func (f formData) SelectedModels() []string {
	out := append([]string{}, f.Key.Models...)
	for _, g := range f.Key.AccessGroups {
		out = append(out, "group:"+g)
	}
	return out
}

func (h *H) form(ctx context.Context, p *auth.Principal, k store.Key, isNew bool) formData {
	fd := formData{Key: k, IsNew: isNew, Models: h.d.Registry.AllModelNames(), AccessGroups: h.d.Registry.AccessGroupNames(),
		Teams: h.manageableTeams(ctx, p), CanSetOwner: p.IsAdmin(), CanSetScope: p.IsAdmin()}
	if p.IsAdmin() {
		fd.Users, _ = h.d.Store.ListUsers(ctx, "", "")
	}
	fd.Guardrails = names(ctx, h.d, `SELECT name FROM guardrails WHERE enabled ORDER BY name`)
	fd.Policies = names(ctx, h.d, `SELECT name FROM guardrail_policies WHERE enabled ORDER BY name`)
	fd.MCPServers = names(ctx, h.d, `SELECT name FROM mcp_servers WHERE enabled ORDER BY name`)
	if isNew {
		fd.ExpiresIn = h.d.Settings.Current().General.DefaultKeyDuration
	}
	return fd
}

func names(ctx context.Context, d *ui.Deps, q string) []string {
	rows, err := d.Store.Pool.Query(ctx, q)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if rows.Scan(&s) == nil {
			out = append(out, s)
		}
	}
	return out
}

func (h *H) newForm(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	if !h.canCreateAny(p) {
		ui.Forbidden(w, r)
		return
	}
	k := store.Key{Scope: "inference", MaxBudget: h.d.Settings.Current().General.DefaultKeyBudget}
	if p.User != nil {
		k.UserID = &p.User.ID
	}
	if t := r.URL.Query().Get("team"); t != "" {
		k.TeamID = &t
	}
	if u := r.URL.Query().Get("user"); u != "" && p.IsAdmin() {
		k.UserID = &u
	}
	h.d.Partial(w, r, 200, area, "key-form", h.form(r.Context(), p, k, true))
}

// bind copies form fields onto k. Ownership/scope changes are only honoured for admins.
func (h *H) bind(r *http.Request, p *auth.Principal, k *store.Key) error {
	_ = r.ParseForm()
	k.Alias = ui.FormStr(r, "alias")
	var models, groups []string
	for _, m := range ui.FormList(r, "models") {
		if len(m) > 6 && m[:6] == "group:" {
			groups = append(groups, m[6:])
		} else {
			models = append(models, m)
		}
	}
	k.Models, k.AccessGroups = models, groups
	k.MaxBudget = ui.FormFloatPtr(r, "max_budget")
	k.BudgetPeriod = ui.FormStr(r, "budget_period")
	k.RPMLimit, k.TPMLimit, k.MaxParallel = ui.FormIntPtr(r, "rpm_limit"), ui.FormIntPtr(r, "tpm_limit"), ui.FormIntPtr(r, "max_parallel")
	k.Tags = ui.FormList(r, "tags")
	k.Guardrails = ui.FormList(r, "guardrails")
	k.Policies = ui.FormList(r, "policies")
	k.MCPServers = ui.FormList(r, "mcp_servers")
	md, err := ui.FormJSONMap(r, "metadata")
	if err != nil {
		return errors.New("metadata must be a JSON object")
	}
	k.Metadata = md
	switch exp := ui.FormStr(r, "expires_in"); exp {
	case "keep":
	case "", "never":
		k.ExpiresAt = nil
	case "custom":
		k.ExpiresAt = ui.FormDatePtr(r, "expires_at")
	default:
		d, ok := store.ParseDuration(exp)
		if !ok {
			return errors.New("invalid expiry")
		}
		t := time.Now().Add(d)
		k.ExpiresAt = &t
	}
	team := store.NullIfEmpty(ui.FormStr(r, "team_id"))
	if team != nil && !p.IsTeamAdmin(*team) {
		return errors.New("you can only create keys for teams you administer")
	}
	k.TeamID = team
	if p.IsAdmin() {
		k.UserID = store.NullIfEmpty(ui.FormStr(r, "user_id"))
		if s := ui.FormStr(r, "scope"); s != "" {
			k.Scope = s
		}
	} else if k.UserID == nil && k.TeamID == nil {
		k.UserID = &p.User.ID
	}
	if k.Scope == "" {
		k.Scope = "inference"
	}
	return nil
}

type createdData struct {
	Key     store.Key
	Plain   string
	Title   string
	BaseURL string
}

func (h *H) create(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	if !h.canCreateAny(p) {
		ui.Forbidden(w, r)
		return
	}
	k := store.Key{}
	if p.User != nil {
		k.UserID = &p.User.ID
	}
	err := h.bind(r, p, &k)
	if err == nil {
		err = p.CheckKeyEdit(nil, &k)
	}
	if err != nil {
		fd := h.form(r.Context(), p, k, true)
		fd.Error = err.Error()
		h.d.Partial(w, r, 422, area, "key-form", fd)
		return
	}
	plain, hash, hint := auth.NewKey()
	k.KeyHash, k.KeyHint, k.CreatedBy = hash, hint, p.Label()
	created, err := h.d.Store.CreateKey(r.Context(), k)
	if err != nil {
		fd := h.form(r.Context(), p, k, true)
		fd.Error = err.Error()
		h.d.Partial(w, r, 422, area, "key-form", fd)
		return
	}
	h.d.Audit(r, "create", "key", created.ID, "Created key "+created.Label(), nil, created)
	ui.Toast(w, "success", "API key created")
	ui.Refresh(w, "refresh-keys")
	h.d.Partial(w, r, 200, area, "key-created", createdData{Key: created, Plain: plain, Title: "Your new API key", BaseURL: h.d.Cfg.BaseURL})
}

func (h *H) load(w http.ResponseWriter, r *http.Request, manage bool) (store.Key, *auth.Principal, bool) {
	p := auth.FromContext(r.Context())
	k, err := h.d.Store.GetKey(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		if ui.IsHTMX(r) {
			ui.Fail(w, 404, "Key not found")
		} else {
			http.NotFound(w, r)
		}
		return k, p, false
	}
	if (manage && !p.CanManageKey(k)) || (!manage && !p.CanViewKey(k)) {
		ui.Forbidden(w, r)
		return k, p, false
	}
	return k, p, true
}

func (h *H) editForm(w http.ResponseWriter, r *http.Request) {
	k, p, ok := h.load(w, r, true)
	if !ok {
		return
	}
	fd := h.form(r.Context(), p, k, false)
	fd.ExpiresIn = "keep"
	h.d.Partial(w, r, 200, area, "key-form", fd)
}

func (h *H) update(w http.ResponseWriter, r *http.Request) {
	k, p, ok := h.load(w, r, true)
	if !ok {
		return
	}
	before := k
	err := h.bind(r, p, &k)
	if err == nil {
		err = p.CheckKeyEdit(&before, &k)
	}
	if err != nil {
		fd := h.form(r.Context(), p, k, false)
		fd.Error = err.Error()
		h.d.Partial(w, r, 422, area, "key-form", fd)
		return
	}
	if err := h.d.Store.UpdateKey(r.Context(), k); err != nil {
		fd := h.form(r.Context(), p, k, false)
		fd.Error = err.Error()
		h.d.Partial(w, r, 422, area, "key-form", fd)
		return
	}
	h.d.Changed()
	h.d.Audit(r, "update", "key", k.ID, "Updated key "+k.Label(), before, k)
	ui.Done(w, "Key updated", "refresh-keys", "refresh-key")
}

func (h *H) regenerate(w http.ResponseWriter, r *http.Request) {
	k, _, ok := h.load(w, r, true)
	if !ok {
		return
	}
	plain, hash, hint := auth.NewKey()
	if err := h.d.Store.RotateKey(r.Context(), k.ID, hash, hint); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	k.KeyHint = hint
	h.d.Changed()
	h.d.Audit(r, "rotate", "key", k.ID, "Regenerated key "+k.Label(), nil, nil)
	ui.Refresh(w, "refresh-keys")
	ui.Refresh(w, "refresh-key")
	h.d.Partial(w, r, 200, area, "key-created", createdData{Key: k, Plain: plain, Title: "Key regenerated", BaseURL: h.d.Cfg.BaseURL})
}

func (h *H) setBlocked(blocked bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		k, p, ok := h.load(w, r, true)
		if !ok {
			return
		}
		if !blocked && k.Blocked && !p.CanUnblockKey(k) {
			ui.Fail(w, 403, "Only an admin can unblock this key.")
			return
		}
		if err := h.d.Store.SetKeyBlocked(r.Context(), k.ID, blocked); err != nil {
			ui.Fail(w, 500, err.Error())
			return
		}
		h.d.Changed()
		verb := "Unblocked"
		if blocked {
			verb = "Blocked"
		}
		h.d.Audit(r, map[bool]string{true: "block", false: "unblock"}[blocked], "key", k.ID, verb+" key "+k.Label(), nil, nil)
		ui.Done(w, verb+" "+k.Label(), "refresh-keys", "refresh-key")
	}
}

func (h *H) resetSpend(w http.ResponseWriter, r *http.Request) {
	k, p, ok := h.load(w, r, true)
	if !ok {
		return
	}
	if !p.IsAdmin() {
		ui.Forbidden(w, r)
		return
	}
	_ = h.d.Store.ResetKeySpend(r.Context(), k.ID)
	h.d.Changed()
	h.d.Audit(r, "reset_spend", "key", k.ID, "Reset spend for key "+k.Label(), map[string]any{"spend": k.Spend}, nil)
	ui.Done(w, "Spend reset", "refresh-keys", "refresh-key")
}

func (h *H) delete(w http.ResponseWriter, r *http.Request) {
	k, _, ok := h.load(w, r, true)
	if !ok {
		return
	}
	_ = h.d.Store.SoftDeleteKey(r.Context(), k.ID)
	h.d.Changed()
	h.d.Audit(r, "delete", "key", k.ID, "Deleted key "+k.Label(), k, nil)
	if r.URL.Query().Get("from") == "detail" {
		ui.Toast(w, "success", "Key deleted")
		ui.Redirect(w, r, "/ui/keys")
		return
	}
	ui.Done(w, "Key deleted", "refresh-keys")
}

func (h *H) restore(w http.ResponseWriter, r *http.Request) {
	k, p, ok := h.load(w, r, true)
	if !ok || !p.IsAdmin() {
		if ok {
			ui.Forbidden(w, r)
		}
		return
	}
	_ = h.d.Store.RestoreKey(r.Context(), k.ID)
	h.d.Changed()
	h.d.Audit(r, "restore", "key", k.ID, "Restored key "+k.Label(), nil, nil)
	ui.Done(w, "Key restored", "refresh-keys")
}

func (h *H) purge(w http.ResponseWriter, r *http.Request) {
	k, p, ok := h.load(w, r, true)
	if !ok || !p.IsAdmin() {
		if ok {
			ui.Forbidden(w, r)
		}
		return
	}
	_ = h.d.Store.PurgeKey(r.Context(), k.ID)
	h.d.Audit(r, "purge", "key", k.ID, "Permanently deleted key "+k.Label(), k, nil)
	ui.Done(w, "Key permanently deleted", "refresh-keys")
}

// --- detail ---

type showData struct {
	Key     store.Key
	CanEdit bool
	IsAdmin bool
	Totals  analytics.Totals
	Chart   analytics.ChartSpec
	ByModel []analytics.Row
	Live    liveUsage
	TPM     float64
	Allowed []string
	BaseURL string
	Days    int
}

func (h *H) show(w http.ResponseWriter, r *http.Request) {
	k, p, ok := h.load(w, r, false)
	if !ok {
		return
	}
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days <= 0 || days > 365 {
		days = 30
	}
	f := analytics.LastDays(days)
	f.KeyID = k.ID
	sd := showData{Key: k, CanEdit: p.CanManageKey(k) && !p.ReadOnly(), IsAdmin: p.IsAdmin(), BaseURL: h.d.Cfg.BaseURL, Days: days}
	sd.Totals, _ = analytics.GetTotals(r.Context(), h.d.Store.Pool, f)
	pts, _ := analytics.Daily(r.Context(), h.d.Store.Pool, f)
	sd.Chart = analytics.DailyChart(pts, "bar", "money", map[string]func(analytics.DayPoint) float64{
		"Spend": func(p analytics.DayPoint) float64 { return p.Cost },
	}, "Spend")
	sd.ByModel, _ = analytics.Breakdown(r.Context(), h.d.Store.Pool, f, "model", 8)
	rpm, tpm, inflight := h.d.Limiter.Usage("key:" + k.ID)
	sd.Live, sd.TPM = liveUsage{RPM: rpm, InFlight: inflight}, tpm
	kp := &auth.Principal{Kind: "key", Key: &k}
	if k.TeamID != nil {
		if t, err := h.d.Store.GetTeam(r.Context(), *k.TeamID); err == nil {
			kp.Team = &t
		}
	}
	sd.Allowed = kp.AllowedModels(h.d.Registry)
	if r.Header.Get("HX-Target") == "key-detail" {
		h.d.Partial(w, r, 200, area, "key-detail", sd)
		return
	}
	h.d.Render(w, r, "keys/show", "keys", k.Label(), sd, ui.Crumb{Label: "API keys", Href: "/ui/keys"})
}

// --- permissions helpers ---

func (h *H) canCreateAny(p *auth.Principal) bool {
	if p.ReadOnly() {
		return false
	}
	if p.IsAdmin() {
		return true
	}
	if h.d.Settings.Current().General.AllowMemberKeys {
		return true
	}
	for _, m := range p.Memberships {
		if m.Role == auth.TeamRoleAdmin {
			return true
		}
	}
	return false
}

func (h *H) visibleTeams(ctx context.Context, p *auth.Principal) []store.Team {
	if p.CanViewAll() {
		t, _ := h.d.Store.ListTeams(ctx, "", "")
		return t
	}
	t, _ := h.d.Store.TeamsForUser(ctx, p.UserID())
	return t
}

func (h *H) manageableTeams(ctx context.Context, p *auth.Principal) []store.Team {
	teams := h.visibleTeams(ctx, p)
	if p.IsAdmin() {
		return teams
	}
	return slices.DeleteFunc(teams, func(t store.Team) bool { return !p.IsTeamAdmin(t.ID) })
}
