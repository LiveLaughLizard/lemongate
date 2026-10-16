// Package orgs is the organization management area. Organizations group teams and
// users under a shared budget, rate limits and model allow-list.
package orgs

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"lemongate/internal/analytics"
	"lemongate/internal/auth"
	"lemongate/internal/store"
	"lemongate/internal/ui"
)

const area = "orgs"

type H struct{ d *ui.Deps }

func Mount(r chi.Router, d *ui.Deps) {
	h := &H{d}
	r.Group(func(r chi.Router) {
		r.Use(ui.AdminWrites)
		r.Get("/ui/orgs", h.index)
		r.Get("/ui/orgs/table", h.table)
		r.Get("/ui/orgs/new", h.newForm)
		r.Post("/ui/orgs", h.create)
		r.Get("/ui/orgs/{id}", h.show)
		r.Get("/ui/orgs/{id}/edit", h.editForm)
		r.Post("/ui/orgs/{id}", h.update)
		r.Post("/ui/orgs/{id}/block", h.setBlocked(true))
		r.Post("/ui/orgs/{id}/unblock", h.setBlocked(false))
		r.Post("/ui/orgs/{id}/reset-spend", h.resetSpend)
		r.Post("/ui/orgs/{id}/delete", h.delete)
		r.Get("/ui/orgs/{id}/teams/add", h.addTeamForm)
		r.Post("/ui/orgs/{id}/teams", h.addTeam)
		r.Post("/ui/orgs/{id}/teams/{tid}/remove", h.removeTeam)
	})
}

func (h *H) index(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	h.d.Render(w, r, "orgs/index", "orgs", "Organizations", map[string]any{"CanCreate": p.IsAdmin()})
}

type tableData struct {
	Orgs []store.Organization
}

func (h *H) table(w http.ResponseWriter, r *http.Request) {
	orgs, err := h.d.Store.ListOrgs(r.Context())
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Partial(w, r, 200, area, "orgs-table", tableData{Orgs: orgs})
}

type formData struct {
	Org    store.Organization
	IsNew  bool
	Error  string
	Models []string
	Groups []string
}

func (h *H) form(o store.Organization, isNew bool, errMsg string) formData {
	return formData{Org: o, IsNew: isNew, Error: errMsg, Models: h.d.Registry.AllModelNames(), Groups: h.d.Registry.AccessGroupNames()}
}

func (h *H) newForm(w http.ResponseWriter, r *http.Request) {
	if !auth.FromContext(r.Context()).IsAdmin() {
		ui.Forbidden(w, r)
		return
	}
	h.d.Partial(w, r, 200, area, "org-form", h.form(store.Organization{}, true, ""))
}

func bind(r *http.Request, o *store.Organization) error {
	_ = r.ParseForm()
	o.Name = ui.FormStr(r, "name")
	if o.Name == "" {
		return errors.New("Organization name is required")
	}
	o.Description = ui.FormStr(r, "description")
	o.Models = ui.FormList(r, "models")
	o.MaxBudget = ui.FormFloatPtr(r, "max_budget")
	o.BudgetPeriod = ui.FormStr(r, "budget_period")
	o.RPMLimit, o.TPMLimit = ui.FormIntPtr(r, "rpm_limit"), ui.FormIntPtr(r, "tpm_limit")
	o.Blocked = ui.FormBool(r, "blocked")
	md, err := ui.FormJSONMap(r, "metadata")
	if err != nil {
		return errors.New("Metadata must be a JSON object")
	}
	o.Metadata = md
	return nil
}

func errText(err error) string {
	if errors.Is(err, store.ErrConflict) {
		return "An organization with that name already exists."
	}
	return err.Error()
}

func (h *H) create(w http.ResponseWriter, r *http.Request) {
	var o store.Organization
	if err := bind(r, &o); err != nil {
		h.d.Partial(w, r, 422, area, "org-form", h.form(o, true, err.Error()))
		return
	}
	created, err := h.d.Store.CreateOrg(r.Context(), o)
	if err != nil {
		h.d.Partial(w, r, 422, area, "org-form", h.form(o, true, errText(err)))
		return
	}
	h.d.Changed()
	h.d.Audit(r, "create", "org", created.ID, "Created organization "+created.Name, nil, created)
	ui.Done(w, "Organization "+created.Name+" created", "refresh-orgs")
}

func (h *H) load(w http.ResponseWriter, r *http.Request) (store.Organization, bool) {
	o, err := h.d.Store.GetOrg(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		if ui.IsHTMX(r) {
			ui.Fail(w, 404, "Organization not found")
		} else {
			http.NotFound(w, r)
		}
		return o, false
	}
	return o, true
}

func (h *H) editForm(w http.ResponseWriter, r *http.Request) {
	o, ok := h.load(w, r)
	if !ok {
		return
	}
	if !auth.FromContext(r.Context()).IsAdmin() {
		ui.Forbidden(w, r)
		return
	}
	h.d.Partial(w, r, 200, area, "org-form", h.form(o, false, ""))
}

func (h *H) update(w http.ResponseWriter, r *http.Request) {
	o, ok := h.load(w, r)
	if !ok {
		return
	}
	before := o
	if err := bind(r, &o); err != nil {
		h.d.Partial(w, r, 422, area, "org-form", h.form(o, false, err.Error()))
		return
	}
	if err := h.d.Store.UpdateOrg(r.Context(), o); err != nil {
		h.d.Partial(w, r, 422, area, "org-form", h.form(o, false, errText(err)))
		return
	}
	h.d.Changed()
	h.d.Audit(r, "update", "org", o.ID, "Updated organization "+o.Name, before, o)
	ui.Done(w, "Organization updated", "refresh-orgs", "refresh-org")
}

func (h *H) setBlocked(blocked bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		o, ok := h.load(w, r)
		if !ok {
			return
		}
		if err := h.d.Store.SetOrgBlocked(r.Context(), o.ID, blocked); err != nil {
			ui.Fail(w, 500, err.Error())
			return
		}
		h.d.Changed()
		verb, action := "Unblocked", "unblock"
		if blocked {
			verb, action = "Blocked", "block"
		}
		h.d.Audit(r, action, "org", o.ID, verb+" organization "+o.Name, nil, nil)
		ui.Done(w, verb+" "+o.Name, "refresh-orgs", "refresh-org")
	}
}

func (h *H) resetSpend(w http.ResponseWriter, r *http.Request) {
	o, ok := h.load(w, r)
	if !ok {
		return
	}
	if _, err := h.d.Store.Pool.Exec(r.Context(), `UPDATE organizations SET spend=0, updated_at=now() WHERE id=$1`, o.ID); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Changed()
	h.d.Audit(r, "reset_spend", "org", o.ID, "Reset spend for organization "+o.Name, map[string]any{"spend": o.Spend}, nil)
	ui.Done(w, "Spend reset", "refresh-orgs", "refresh-org")
}

func (h *H) delete(w http.ResponseWriter, r *http.Request) {
	o, ok := h.load(w, r)
	if !ok {
		return
	}
	if err := h.d.Store.DeleteOrg(r.Context(), o.ID); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Changed()
	h.d.Audit(r, "delete", "org", o.ID, "Deleted organization "+o.Name, o, nil)
	if r.URL.Query().Get("from") == "detail" {
		ui.Toast(w, "success", "Organization deleted")
		ui.Redirect(w, r, "/ui/orgs")
		return
	}
	ui.Done(w, "Organization deleted", "refresh-orgs")
}

// --- detail ---

type showData struct {
	Org     store.Organization
	IsAdmin bool
	Teams   []store.Team
	Users   []store.User
	Totals  analytics.Totals
	Chart   analytics.ChartSpec
	ByTeam  []analytics.Row
	ByModel []analytics.Row
	RPM     float64
	TPM     float64
	Days    int
}

func (h *H) show(w http.ResponseWriter, r *http.Request) {
	o, ok := h.load(w, r)
	if !ok {
		return
	}
	p := auth.FromContext(r.Context())
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days <= 0 || days > 365 {
		days = 30
	}
	f := analytics.LastDays(days)
	f.OrgID = o.ID
	sd := showData{Org: o, IsAdmin: p.IsAdmin(), Days: days}
	sd.Teams, _ = h.d.Store.ListTeams(r.Context(), "", o.ID)
	sd.Users, _ = h.d.Store.ListUsersInOrg(r.Context(), o.ID)
	sd.Totals, _ = analytics.GetTotals(r.Context(), h.d.Store.Pool, f)
	pts, _ := analytics.Daily(r.Context(), h.d.Store.Pool, f)
	sd.Chart = analytics.DailyChart(pts, "bar", "money", map[string]func(analytics.DayPoint) float64{
		"Spend": func(p analytics.DayPoint) float64 { return p.Cost },
	}, "Spend")
	sd.ByTeam, _ = analytics.Breakdown(r.Context(), h.d.Store.Pool, f, "team", 6)
	sd.ByModel, _ = analytics.Breakdown(r.Context(), h.d.Store.Pool, f, "model", 6)
	sd.RPM, sd.TPM, _ = h.d.Limiter.Usage("org:" + o.ID)
	if r.Header.Get("HX-Target") == "org-detail" {
		h.d.Partial(w, r, 200, area, "org-detail", sd)
		return
	}
	h.d.Render(w, r, "orgs/show", "orgs", o.Name, sd, ui.Crumb{Label: "Organizations", Href: "/ui/orgs"})
}

// --- team assignment ---

type addTeamData struct {
	Org   store.Organization
	Teams []store.Team
	Error string
}

func (h *H) addTeamForm(w http.ResponseWriter, r *http.Request) {
	o, ok := h.load(w, r)
	if !ok {
		return
	}
	if !auth.FromContext(r.Context()).IsAdmin() {
		ui.Forbidden(w, r)
		return
	}
	all, _ := h.d.Store.ListTeams(r.Context(), "", "")
	var cands []store.Team
	for _, t := range all {
		if t.OrgID == nil || *t.OrgID != o.ID {
			cands = append(cands, t)
		}
	}
	h.d.Partial(w, r, 200, area, "org-add-team", addTeamData{Org: o, Teams: cands})
}

func (h *H) addTeam(w http.ResponseWriter, r *http.Request) {
	o, ok := h.load(w, r)
	if !ok {
		return
	}
	_ = r.ParseForm()
	ids := ui.FormList(r, "team_id")
	if len(ids) == 0 {
		ui.Fail(w, 422, "Choose at least one team")
		return
	}
	for _, id := range ids {
		t, err := h.d.Store.GetTeam(r.Context(), id)
		if err != nil {
			continue
		}
		if err := h.d.Store.SetTeamOrg(r.Context(), t.ID, &o.ID); err == nil {
			h.d.Audit(r, "update", "team", t.ID, "Moved team "+t.Name+" into organization "+o.Name,
				map[string]any{"org_id": t.OrgID}, map[string]any{"org_id": o.ID})
		}
	}
	h.d.Changed()
	ui.Done(w, "Teams added to "+o.Name, "refresh-org")
}

func (h *H) removeTeam(w http.ResponseWriter, r *http.Request) {
	o, ok := h.load(w, r)
	if !ok {
		return
	}
	t, err := h.d.Store.GetTeam(r.Context(), chi.URLParam(r, "tid"))
	if err != nil || t.OrgID == nil || *t.OrgID != o.ID {
		ui.Fail(w, 404, "Team not found in this organization")
		return
	}
	if err := h.d.Store.SetTeamOrg(r.Context(), t.ID, nil); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Changed()
	h.d.Audit(r, "update", "team", t.ID, "Removed team "+t.Name+" from organization "+o.Name,
		map[string]any{"org_id": o.ID}, map[string]any{"org_id": nil})
	ui.Done(w, t.Name+" removed from "+o.Name, "refresh-org")
}
