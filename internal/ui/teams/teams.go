// Package teams is the team management area: teams, their members, budgets and keys.
// Admins manage every team; team admins manage members of their own teams;
// members see only the teams they belong to.
package teams

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"lemongate/internal/analytics"
	"lemongate/internal/auth"
	"lemongate/internal/store"
	"lemongate/internal/ui"
)

const area = "teams"

type H struct{ d *ui.Deps }

func Mount(r chi.Router, d *ui.Deps) {
	h := &H{d}
	r.Get("/ui/teams", h.index)
	r.Get("/ui/teams/table", h.table)
	r.Get("/ui/teams/new", h.newForm)
	r.Post("/ui/teams", h.create)
	r.Get("/ui/teams/{id}", h.show)
	r.Get("/ui/teams/{id}/edit", h.editForm)
	r.Post("/ui/teams/{id}", h.update)
	r.Post("/ui/teams/{id}/block", h.setBlocked(true))
	r.Post("/ui/teams/{id}/unblock", h.setBlocked(false))
	r.Post("/ui/teams/{id}/reset-spend", h.resetSpend)
	r.Post("/ui/teams/{id}/delete", h.delete)
	r.Post("/ui/teams/{id}/restore", h.restore)
	r.Post("/ui/teams/{id}/purge", h.purge)
	r.Get("/ui/teams/{id}/members", h.members)
	r.Get("/ui/teams/{id}/members/new", h.memberForm)
	r.Post("/ui/teams/{id}/members", h.addMember)
	r.Get("/ui/teams/{id}/members/{uid}/edit", h.memberEditForm)
	r.Post("/ui/teams/{id}/members/{uid}", h.updateMember)
	r.Post("/ui/teams/{id}/members/{uid}/remove", h.removeMember)
	r.Get("/ui/teams/{id}/keys", h.keys)
}

// --- listing ---

type indexData struct {
	CanCreate bool
	Deleted   bool
	Orgs      []store.Organization
}

func (h *H) index(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	deleted := r.URL.Query().Get("deleted") == "1" && p.CanViewAll()
	data := indexData{CanCreate: p.IsAdmin(), Deleted: deleted}
	if p.CanViewAll() {
		data.Orgs, _ = h.d.Store.ListOrgs(r.Context())
	}
	h.d.Render(w, r, "teams/index", "teams", "Teams", data)
}

type tableData struct {
	Teams   []store.Team
	Deleted bool
	Roles   map[string]string // team id → caller's team role
}

func (h *H) table(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	q := r.URL.Query()
	deleted := q.Get("deleted") == "1" && p.CanViewAll()
	var teams []store.Team
	var err error
	switch {
	case deleted:
		teams, err = h.d.Store.ListDeletedTeams(r.Context())
	case p.CanViewAll():
		teams, err = h.d.Store.ListTeams(r.Context(), q.Get("q"), q.Get("org"))
	default:
		teams, err = h.d.Store.TeamsForUser(r.Context(), p.UserID())
		if s := strings.ToLower(q.Get("q")); s != "" {
			teams = slices.DeleteFunc(teams, func(t store.Team) bool { return !strings.Contains(strings.ToLower(t.Name), s) })
		}
	}
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	roles := map[string]string{}
	for _, m := range p.Memberships {
		roles[m.TeamID] = m.Role
	}
	h.d.Partial(w, r, 200, area, "teams-table", tableData{Teams: teams, Deleted: deleted, Roles: roles})
}

// --- create / edit ---

type formData struct {
	Team       store.Team
	IsNew      bool
	Error      string
	Orgs       []store.Organization
	Models     []string
	Groups     []string
	Guardrails []string
	Policies   []string
	MCPServers []string
}

func (h *H) form(ctx context.Context, t store.Team, isNew bool) formData {
	fd := formData{Team: t, IsNew: isNew, Models: h.d.Registry.AllModelNames(), Groups: h.d.Registry.AccessGroupNames()}
	fd.Orgs, _ = h.d.Store.ListOrgs(ctx)
	fd.Guardrails = names(ctx, h.d, `SELECT name FROM guardrails WHERE enabled ORDER BY name`)
	fd.Policies = names(ctx, h.d, `SELECT name FROM guardrail_policies WHERE enabled ORDER BY name`)
	fd.MCPServers = names(ctx, h.d, `SELECT name FROM mcp_servers WHERE enabled ORDER BY name`)
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
	if !p.IsAdmin() {
		ui.Forbidden(w, r)
		return
	}
	t := store.Team{}
	if o := r.URL.Query().Get("org"); o != "" {
		t.OrgID = &o
	}
	h.d.Partial(w, r, 200, area, "team-form", h.form(r.Context(), t, true))
}

func bind(r *http.Request, t *store.Team) error {
	_ = r.ParseForm()
	t.Name = ui.FormStr(r, "name")
	if t.Name == "" {
		return errors.New("Team name is required")
	}
	t.Description = ui.FormStr(r, "description")
	t.OrgID = store.NullIfEmpty(ui.FormStr(r, "org_id"))
	t.Models = ui.FormList(r, "models")
	t.MaxBudget = ui.FormFloatPtr(r, "max_budget")
	t.BudgetPeriod = ui.FormStr(r, "budget_period")
	t.MemberMaxBudget = ui.FormFloatPtr(r, "member_max_budget")
	t.RPMLimit, t.TPMLimit, t.MaxParallel = ui.FormIntPtr(r, "rpm_limit"), ui.FormIntPtr(r, "tpm_limit"), ui.FormIntPtr(r, "max_parallel")
	t.Guardrails = ui.FormList(r, "guardrails")
	t.Policies = ui.FormList(r, "policies")
	t.MCPServers = ui.FormList(r, "mcp_servers")
	t.Blocked = ui.FormBool(r, "blocked")
	md, err := ui.FormJSONMap(r, "metadata")
	if err != nil {
		return errors.New("Metadata must be a JSON object")
	}
	t.Metadata = md
	return nil
}

func (h *H) fail(w http.ResponseWriter, r *http.Request, t store.Team, isNew bool, err error) {
	fd := h.form(r.Context(), t, isNew)
	fd.Error = err.Error()
	if errors.Is(err, store.ErrConflict) {
		fd.Error = "A team with that name already exists."
	}
	h.d.Partial(w, r, 422, area, "team-form", fd)
}

func (h *H) create(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	if !p.IsAdmin() {
		ui.Forbidden(w, r)
		return
	}
	var t store.Team
	if err := bind(r, &t); err != nil {
		h.fail(w, r, t, true, err)
		return
	}
	if existing, err := h.d.Store.GetTeamByName(r.Context(), t.Name); err == nil && existing.ID != "" {
		h.fail(w, r, t, true, store.ErrConflict)
		return
	}
	created, err := h.d.Store.CreateTeam(r.Context(), t)
	if err != nil {
		h.fail(w, r, t, true, err)
		return
	}
	h.d.Changed()
	h.d.Audit(r, "create", "team", created.ID, "Created team "+created.Name, nil, created)
	ui.Done(w, "Team "+created.Name+" created", "refresh-teams")
}

// load fetches the team from the URL and checks access. manage requires admin.
func (h *H) load(w http.ResponseWriter, r *http.Request, manage bool) (store.Team, *auth.Principal, bool) {
	p := auth.FromContext(r.Context())
	t, err := h.d.Store.GetTeam(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		if ui.IsHTMX(r) {
			ui.Fail(w, 404, "Team not found")
		} else {
			http.NotFound(w, r)
		}
		return t, p, false
	}
	canView := p.CanViewAll() || (t.DeletedAt == nil && p.InTeam(t.ID))
	if !canView || (manage && !p.IsAdmin()) {
		ui.Forbidden(w, r)
		return t, p, false
	}
	return t, p, true
}

func (h *H) editForm(w http.ResponseWriter, r *http.Request) {
	t, _, ok := h.load(w, r, true)
	if !ok {
		return
	}
	h.d.Partial(w, r, 200, area, "team-form", h.form(r.Context(), t, false))
}

func (h *H) update(w http.ResponseWriter, r *http.Request) {
	t, _, ok := h.load(w, r, true)
	if !ok {
		return
	}
	before := t
	if err := bind(r, &t); err != nil {
		h.fail(w, r, t, false, err)
		return
	}
	if existing, err := h.d.Store.GetTeamByName(r.Context(), t.Name); err == nil && existing.ID != t.ID {
		h.fail(w, r, t, false, store.ErrConflict)
		return
	}
	if err := h.d.Store.UpdateTeam(r.Context(), t); err != nil {
		h.fail(w, r, t, false, err)
		return
	}
	h.d.Changed()
	h.d.Audit(r, "update", "team", t.ID, "Updated team "+t.Name, before, t)
	ui.Done(w, "Team updated", "refresh-teams", "refresh-team")
}

func (h *H) setBlocked(blocked bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t, _, ok := h.load(w, r, true)
		if !ok {
			return
		}
		if err := h.d.Store.SetTeamBlocked(r.Context(), t.ID, blocked); err != nil {
			ui.Fail(w, 500, err.Error())
			return
		}
		h.d.Changed()
		verb, action := "Unblocked", "unblock"
		if blocked {
			verb, action = "Blocked", "block"
		}
		h.d.Audit(r, action, "team", t.ID, verb+" team "+t.Name, nil, nil)
		ui.Done(w, verb+" "+t.Name, "refresh-teams", "refresh-team")
	}
}

func (h *H) resetSpend(w http.ResponseWriter, r *http.Request) {
	t, _, ok := h.load(w, r, true)
	if !ok {
		return
	}
	if _, err := h.d.Store.Pool.Exec(r.Context(), `UPDATE teams SET spend=0, updated_at=now() WHERE id=$1`, t.ID); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Changed()
	h.d.Audit(r, "reset_spend", "team", t.ID, "Reset spend for team "+t.Name, map[string]any{"spend": t.Spend}, nil)
	ui.Done(w, "Spend reset", "refresh-teams", "refresh-team")
}

func (h *H) delete(w http.ResponseWriter, r *http.Request) {
	t, _, ok := h.load(w, r, true)
	if !ok {
		return
	}
	_ = h.d.Store.SoftDeleteTeam(r.Context(), t.ID)
	h.d.Changed()
	h.d.Audit(r, "delete", "team", t.ID, "Deleted team "+t.Name, t, nil)
	if r.URL.Query().Get("from") == "detail" {
		ui.Toast(w, "success", "Team deleted")
		ui.Redirect(w, r, "/ui/teams")
		return
	}
	ui.Done(w, "Team deleted", "refresh-teams")
}

func (h *H) restore(w http.ResponseWriter, r *http.Request) {
	t, _, ok := h.load(w, r, true)
	if !ok {
		return
	}
	if err := h.d.Store.RestoreTeam(r.Context(), t.ID); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Changed()
	h.d.Audit(r, "restore", "team", t.ID, "Restored team "+t.Name, nil, nil)
	ui.Done(w, "Team restored", "refresh-teams")
}

func (h *H) purge(w http.ResponseWriter, r *http.Request) {
	t, _, ok := h.load(w, r, true)
	if !ok {
		return
	}
	if t.DeletedAt == nil {
		ui.Fail(w, 400, "Delete the team before purging it")
		return
	}
	if err := h.d.Store.PurgeTeam(r.Context(), t.ID); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Changed()
	h.d.Audit(r, "purge", "team", t.ID, "Permanently deleted team "+t.Name, t, nil)
	ui.Done(w, "Team permanently deleted", "refresh-teams")
}

// --- detail ---

type showData struct {
	Team      store.Team
	IsAdmin   bool
	CanManage bool // members & keys
	MyRole    string
	Totals    analytics.Totals
	Chart     analytics.ChartSpec
	ByModel   []analytics.Row
	ByUser    []analytics.Row
	RPM, TPM  float64
	InFlight  int
	Allowed   []string
	AllModels bool
	Days      int
}

func (h *H) show(w http.ResponseWriter, r *http.Request) {
	t, p, ok := h.load(w, r, false)
	if !ok {
		return
	}
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days <= 0 || days > 365 {
		days = 30
	}
	f := analytics.LastDays(days)
	f.TeamID = t.ID
	sd := showData{Team: t, IsAdmin: p.IsAdmin(), CanManage: p.IsTeamAdmin(t.ID) && !p.ReadOnly() && t.DeletedAt == nil, Days: days}
	for _, m := range p.Memberships {
		if m.TeamID == t.ID {
			sd.MyRole = m.Role
		}
	}
	sd.Totals, _ = analytics.GetTotals(r.Context(), h.d.Store.Pool, f)
	pts, _ := analytics.Daily(r.Context(), h.d.Store.Pool, f)
	sd.Chart = analytics.DailyChart(pts, "bar", "money", map[string]func(analytics.DayPoint) float64{
		"Spend": func(p analytics.DayPoint) float64 { return p.Cost },
	}, "Spend")
	sd.ByModel, _ = analytics.Breakdown(r.Context(), h.d.Store.Pool, f, "model", 6)
	sd.ByUser, _ = analytics.Breakdown(r.Context(), h.d.Store.Pool, f, "user", 6)
	sd.RPM, sd.TPM, sd.InFlight = h.d.Limiter.Usage("team:" + t.ID)
	tp := &auth.Principal{Kind: "key", Team: &t}
	if t.OrgID != nil {
		if o, err := h.d.Store.GetOrg(r.Context(), *t.OrgID); err == nil {
			tp.Org = &o
		}
	}
	sd.Allowed = tp.AllowedModels(h.d.Registry)
	if sd.Allowed != nil {
		slices.Sort(sd.Allowed)
		sd.Allowed = slices.Compact(sd.Allowed)
	}
	sd.AllModels = sd.Allowed == nil
	if r.Header.Get("HX-Target") == "team-detail" {
		h.d.Partial(w, r, 200, area, "team-detail", sd)
		return
	}
	h.d.Render(w, r, "teams/show", "teams", t.Name, sd, ui.Crumb{Label: "Teams", Href: "/ui/teams"})
}

// --- members ---

type membersData struct {
	Team      store.Team
	Members   []store.TeamMember
	CanManage bool
	SelfID    string
}

func (h *H) members(w http.ResponseWriter, r *http.Request) {
	t, p, ok := h.load(w, r, false)
	if !ok {
		return
	}
	ms, err := h.d.Store.ListTeamMembers(r.Context(), t.ID)
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Partial(w, r, 200, area, "team-members", membersData{Team: t, Members: ms,
		CanManage: p.IsTeamAdmin(t.ID) && !p.ReadOnly() && t.DeletedAt == nil, SelfID: p.UserID()})
}

type memberFormData struct {
	Team   store.Team
	Member store.TeamMember
	IsNew  bool
	Error  string
	Emails []string // suggestions (admins only)
}

// loadManage loads a team the caller may manage members of.
func (h *H) loadManage(w http.ResponseWriter, r *http.Request) (store.Team, *auth.Principal, bool) {
	t, p, ok := h.load(w, r, false)
	if !ok {
		return t, p, false
	}
	if !p.IsTeamAdmin(t.ID) || p.ReadOnly() || t.DeletedAt != nil {
		ui.Forbidden(w, r)
		return t, p, false
	}
	return t, p, true
}

func (h *H) memberFormFor(ctx context.Context, p *auth.Principal, t store.Team, m store.TeamMember, isNew bool) memberFormData {
	fd := memberFormData{Team: t, Member: m, IsNew: isNew}
	if isNew && p.IsAdmin() {
		users, _ := h.d.Store.ListUsers(ctx, "", "")
		existing, _ := h.d.Store.ListTeamMembers(ctx, t.ID)
		in := map[string]bool{}
		for _, e := range existing {
			in[e.UserID] = true
		}
		for _, u := range users {
			if !in[u.ID] {
				fd.Emails = append(fd.Emails, u.Email)
			}
		}
	}
	return fd
}

func (h *H) memberForm(w http.ResponseWriter, r *http.Request) {
	t, p, ok := h.loadManage(w, r)
	if !ok {
		return
	}
	h.d.Partial(w, r, 200, area, "member-form", h.memberFormFor(r.Context(), p, t, store.TeamMember{Role: auth.TeamRoleMember}, true))
}

func memberRole(r *http.Request) string {
	if ui.FormStr(r, "role") == auth.TeamRoleAdmin {
		return auth.TeamRoleAdmin
	}
	return auth.TeamRoleMember
}

func (h *H) addMember(w http.ResponseWriter, r *http.Request) {
	t, p, ok := h.loadManage(w, r)
	if !ok {
		return
	}
	_ = r.ParseForm()
	m := store.TeamMember{Email: ui.FormStr(r, "email"), Role: memberRole(r), MaxBudget: ui.FormFloatPtr(r, "max_budget")}
	failf := func(msg string) {
		fd := h.memberFormFor(r.Context(), p, t, m, true)
		fd.Error = msg
		h.d.Partial(w, r, 422, area, "member-form", fd)
	}
	if m.Email == "" {
		failf("Enter the email address of an existing user.")
		return
	}
	u, err := h.d.Store.GetUserByEmail(r.Context(), m.Email)
	if err != nil {
		failf("No user with that email exists. An admin can invite them from the Users page first.")
		return
	}
	if _, err := h.d.Store.GetMembership(r.Context(), t.ID, u.ID); err == nil {
		failf(u.Email + " is already a member of this team.")
		return
	}
	if err := h.d.Store.UpsertTeamMember(r.Context(), t.ID, u.ID, m.Role, m.MaxBudget); err != nil {
		failf(err.Error())
		return
	}
	h.d.Changed()
	h.d.Audit(r, "add_member", "team", t.ID, "Added "+u.Email+" to team "+t.Name+" as "+auth.RoleLabel(m.Role), nil,
		map[string]any{"user_id": u.ID, "email": u.Email, "role": m.Role, "max_budget": m.MaxBudget})
	ui.Done(w, u.Email+" added to "+t.Name, "refresh-members", "refresh-team")
}

func (h *H) memberEditForm(w http.ResponseWriter, r *http.Request) {
	t, p, ok := h.loadManage(w, r)
	if !ok {
		return
	}
	m, err := h.d.Store.GetMembership(r.Context(), t.ID, chi.URLParam(r, "uid"))
	if err != nil {
		ui.Fail(w, 404, "Member not found")
		return
	}
	h.d.Partial(w, r, 200, area, "member-form", h.memberFormFor(r.Context(), p, t, m, false))
}

func (h *H) updateMember(w http.ResponseWriter, r *http.Request) {
	t, p, ok := h.loadManage(w, r)
	if !ok {
		return
	}
	m, err := h.d.Store.GetMembership(r.Context(), t.ID, chi.URLParam(r, "uid"))
	if err != nil {
		ui.Fail(w, 404, "Member not found")
		return
	}
	before := m
	_ = r.ParseForm()
	m.Role, m.MaxBudget = memberRole(r), ui.FormFloatPtr(r, "max_budget")
	if m.UserID == p.UserID() && m.Role != auth.TeamRoleAdmin && !p.IsAdmin() {
		fd := h.memberFormFor(r.Context(), p, t, m, false)
		fd.Error = "You can't remove your own team admin role."
		h.d.Partial(w, r, 422, area, "member-form", fd)
		return
	}
	if m.UserID == p.UserID() && !p.IsAdmin() && !sameBudget(before.MaxBudget, m.MaxBudget) {
		fd := h.memberFormFor(r.Context(), p, t, m, false)
		fd.Error = "You can't change your own member budget. Ask an admin."
		h.d.Partial(w, r, 422, area, "member-form", fd)
		return
	}
	if err := h.d.Store.UpsertTeamMember(r.Context(), t.ID, m.UserID, m.Role, m.MaxBudget); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Changed()
	h.d.Audit(r, "update_member", "team", t.ID, "Updated "+m.Email+" in team "+t.Name, before, m)
	ui.Done(w, "Member updated", "refresh-members")
}

func (h *H) removeMember(w http.ResponseWriter, r *http.Request) {
	t, p, ok := h.loadManage(w, r)
	if !ok {
		return
	}
	m, err := h.d.Store.GetMembership(r.Context(), t.ID, chi.URLParam(r, "uid"))
	if err != nil {
		ui.Fail(w, 404, "Member not found")
		return
	}
	if m.UserID == p.UserID() && !p.IsAdmin() {
		ui.Fail(w, 400, "You can't remove yourself. Ask another team admin.")
		return
	}
	if err := h.d.Store.RemoveTeamMember(r.Context(), t.ID, m.UserID); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Changed()
	h.d.Audit(r, "remove_member", "team", t.ID, "Removed "+m.Email+" from team "+t.Name, m, nil)
	ui.Done(w, m.Email+" removed", "refresh-members", "refresh-team")
}

// --- keys ---

type keysData struct {
	Team      store.Team
	Keys      []store.Key
	CanCreate bool
}

func (h *H) keys(w http.ResponseWriter, r *http.Request) {
	t, p, ok := h.load(w, r, false)
	if !ok {
		return
	}
	keys, err := h.d.Store.ListKeys(r.Context(), store.KeyFilter{TeamID: t.ID})
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Partial(w, r, 200, area, "team-keys", keysData{Team: t, Keys: keys, CanCreate: p.IsTeamAdmin(t.ID) && !p.ReadOnly() && t.DeletedAt == nil})
}

func sameBudget(a, b *float64) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}
