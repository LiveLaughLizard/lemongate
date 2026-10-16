package api

import (
	"net/http"
	"slices"
	"strings"

	"lemongate/internal/auth"
	"lemongate/internal/store"
)

// --- users ---

type userInput struct {
	*store.User
	Password *string `json:"password"`
}

func validateUser(u *store.User) string {
	u.Email = strings.TrimSpace(u.Email)
	if u.Email == "" || !strings.Contains(u.Email, "@") {
		return "a valid email is required"
	}
	if u.Role == "" {
		u.Role = auth.RoleMember
	}
	if !slices.Contains(auth.Roles, u.Role) {
		return "role must be one of " + strings.Join(auth.Roles, ", ")
	}
	if !validPeriod(u.BudgetPeriod) {
		return "invalid budget_period"
	}
	return ""
}

func (h *H) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.d.Store.ListUsers(r.Context(), r.URL.Query().Get("q"), r.URL.Query().Get("role"))
	if err != nil {
		storeErr(w, err, "users")
		return
	}
	writeJSON(w, 200, list(users))
}

func (h *H) getUser(w http.ResponseWriter, r *http.Request) {
	u, err := h.d.Store.GetUser(r.Context(), param(r, "id"))
	if err != nil {
		storeErr(w, err, "user")
		return
	}
	writeJSON(w, 200, u)
}

func (h *H) createUser(w http.ResponseWriter, r *http.Request) {
	u := store.User{Role: auth.RoleMember}
	in := userInput{User: &u}
	if !decode(w, r, &in) {
		return
	}
	u.SSOSubject = nil
	if msg := validateUser(&u); msg != "" {
		badRequest(w, "%s", msg)
		return
	}
	if in.Password != nil && *in.Password != "" {
		if len(*in.Password) < 8 {
			badRequest(w, "password must be at least 8 characters")
			return
		}
		u.PasswordHash, _ = auth.HashPassword(*in.Password)
	}
	created, err := h.d.Store.CreateUser(r.Context(), u)
	if err != nil {
		storeErr(w, err, "user")
		return
	}
	h.d.Changed()
	h.d.Audit(r, "create", "user", created.ID, "Created user "+created.Email+" via API", nil, created)
	writeJSON(w, 201, created)
}

func (h *H) updateUser(w http.ResponseWriter, r *http.Request) {
	u, err := h.d.Store.GetUser(r.Context(), param(r, "id"))
	if err != nil {
		storeErr(w, err, "user")
		return
	}
	before := u
	in := userInput{User: &u}
	if !decode(w, r, &in) {
		return
	}
	u.ID, u.Spend, u.CreatedAt, u.SSOSubject, u.PasswordHash = before.ID, before.Spend, before.CreatedAt, before.SSOSubject, before.PasswordHash
	if msg := validateUser(&u); msg != "" {
		badRequest(w, "%s", msg)
		return
	}
	if err := h.d.Store.UpdateUser(r.Context(), u); err != nil {
		storeErr(w, err, "user")
		return
	}
	if in.Password != nil && *in.Password != "" {
		if len(*in.Password) < 8 {
			badRequest(w, "password must be at least 8 characters")
			return
		}
		hash, _ := auth.HashPassword(*in.Password)
		_ = h.d.Store.SetUserPassword(r.Context(), u.ID, hash)
	}
	if u.Blocked && !before.Blocked {
		_ = h.d.Store.DeleteUserSessions(r.Context(), u.ID)
	}
	h.d.Changed()
	h.d.Audit(r, "update", "user", u.ID, "Updated user "+u.Email+" via API", before, u)
	u, _ = h.d.Store.GetUser(r.Context(), u.ID)
	writeJSON(w, 200, u)
}

func (h *H) deleteUser(w http.ResponseWriter, r *http.Request) {
	u, err := h.d.Store.GetUser(r.Context(), param(r, "id"))
	if err != nil {
		storeErr(w, err, "user")
		return
	}
	if principal(r).UserID() == u.ID {
		badRequest(w, "you cannot delete yourself")
		return
	}
	if err := h.d.Store.DeleteUser(r.Context(), u.ID); err != nil {
		storeErr(w, err, "user")
		return
	}
	h.d.Changed()
	h.d.Audit(r, "delete", "user", u.ID, "Deleted user "+u.Email+" via API", u, nil)
	writeJSON(w, 200, deleted(u.ID))
}

// --- teams ---

func validateTeam(t *store.Team) string {
	t.Name = strings.TrimSpace(t.Name)
	if t.Name == "" {
		return "name is required"
	}
	if !validPeriod(t.BudgetPeriod) {
		return "invalid budget_period"
	}
	return ""
}

func (h *H) listTeams(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	var teams []store.Team
	var err error
	if p.CanViewAll() {
		teams, err = h.d.Store.ListTeams(r.Context(), r.URL.Query().Get("q"), r.URL.Query().Get("org_id"))
	} else {
		teams, err = h.d.Store.TeamsForUser(r.Context(), p.UserID())
		if p.User == nil && p.Team != nil {
			teams = []store.Team{*p.Team}
		}
	}
	if err != nil {
		storeErr(w, err, "teams")
		return
	}
	writeJSON(w, 200, list(teams))
}

func canSeeTeam(p *auth.Principal, id string) bool {
	return p.CanViewAll() || p.InTeam(id) || p.TeamID() == id
}

func (h *H) loadTeam(w http.ResponseWriter, r *http.Request) (store.Team, bool) {
	id := param(r, "id")
	if !canSeeTeam(principal(r), id) {
		notFound(w, "team")
		return store.Team{}, false
	}
	t, err := h.d.Store.GetTeam(r.Context(), id)
	if err != nil {
		storeErr(w, err, "team")
		return t, false
	}
	return t, true
}

func (h *H) getTeam(w http.ResponseWriter, r *http.Request) {
	if t, ok := h.loadTeam(w, r); ok {
		writeJSON(w, 200, t)
	}
}

func (h *H) createTeam(w http.ResponseWriter, r *http.Request) {
	var t store.Team
	if !decode(w, r, &t) {
		return
	}
	if msg := validateTeam(&t); msg != "" {
		badRequest(w, "%s", msg)
		return
	}
	created, err := h.d.Store.CreateTeam(r.Context(), t)
	if err != nil {
		storeErr(w, err, "team")
		return
	}
	h.d.Changed()
	h.d.Audit(r, "create", "team", created.ID, "Created team "+created.Name+" via API", nil, created)
	writeJSON(w, 201, created)
}

func (h *H) updateTeam(w http.ResponseWriter, r *http.Request) {
	t, err := h.d.Store.GetTeam(r.Context(), param(r, "id"))
	if err != nil {
		storeErr(w, err, "team")
		return
	}
	before := t
	if !decode(w, r, &t) {
		return
	}
	t.ID, t.Spend, t.CreatedAt, t.DeletedAt = before.ID, before.Spend, before.CreatedAt, before.DeletedAt
	if msg := validateTeam(&t); msg != "" {
		badRequest(w, "%s", msg)
		return
	}
	if err := h.d.Store.UpdateTeam(r.Context(), t); err != nil {
		storeErr(w, err, "team")
		return
	}
	h.d.Changed()
	h.d.Audit(r, "update", "team", t.ID, "Updated team "+t.Name+" via API", before, t)
	t, _ = h.d.Store.GetTeam(r.Context(), t.ID)
	writeJSON(w, 200, t)
}

func (h *H) deleteTeam(w http.ResponseWriter, r *http.Request) {
	t, err := h.d.Store.GetTeam(r.Context(), param(r, "id"))
	if err != nil {
		storeErr(w, err, "team")
		return
	}
	if err := h.d.Store.SoftDeleteTeam(r.Context(), t.ID); err != nil {
		storeErr(w, err, "team")
		return
	}
	h.d.Changed()
	h.d.Audit(r, "delete", "team", t.ID, "Deleted team "+t.Name+" via API", t, nil)
	writeJSON(w, 200, deleted(t.ID))
}

func (h *H) listMembers(w http.ResponseWriter, r *http.Request) {
	t, ok := h.loadTeam(w, r)
	if !ok {
		return
	}
	m, err := h.d.Store.ListTeamMembers(r.Context(), t.ID)
	if err != nil {
		storeErr(w, err, "members")
		return
	}
	writeJSON(w, 200, list(m))
}

type memberInput struct {
	UserID    string   `json:"user_id"`
	Email     string   `json:"email"`
	Role      string   `json:"role"`
	MaxBudget *float64 `json:"max_budget"`
}

func (h *H) addMember(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	t, ok := h.loadTeam(w, r)
	if !ok {
		return
	}
	if !p.IsTeamAdmin(t.ID) {
		forbidden(w, "team admin role required")
		return
	}
	var in memberInput
	if !decode(w, r, &in) {
		return
	}
	if in.Role == "" {
		in.Role = auth.TeamRoleMember
	}
	if in.Role != auth.TeamRoleMember && in.Role != auth.TeamRoleAdmin {
		badRequest(w, "role must be team_member or team_admin")
		return
	}
	var u store.User
	var err error
	switch {
	case in.UserID != "":
		u, err = h.d.Store.GetUser(r.Context(), in.UserID)
	case in.Email != "":
		u, err = h.d.Store.GetUserByEmail(r.Context(), in.Email)
	default:
		badRequest(w, "user_id or email is required")
		return
	}
	if err != nil {
		storeErr(w, err, "user")
		return
	}
	if err := h.d.Store.UpsertTeamMember(r.Context(), t.ID, u.ID, in.Role, in.MaxBudget); err != nil {
		storeErr(w, err, "member")
		return
	}
	h.d.Changed()
	h.d.Audit(r, "add_member", "team", t.ID, "Added "+u.Email+" to team "+t.Name+" as "+in.Role+" via API", nil, in)
	m, err := h.d.Store.GetMembership(r.Context(), t.ID, u.ID)
	if err != nil {
		storeErr(w, err, "member")
		return
	}
	writeJSON(w, 200, m)
}

func (h *H) removeMember(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	t, ok := h.loadTeam(w, r)
	if !ok {
		return
	}
	if !p.IsTeamAdmin(t.ID) {
		forbidden(w, "team admin role required")
		return
	}
	uid := param(r, "user_id")
	if err := h.d.Store.RemoveTeamMember(r.Context(), t.ID, uid); err != nil {
		storeErr(w, err, "member")
		return
	}
	h.d.Changed()
	h.d.Audit(r, "remove_member", "team", t.ID, "Removed user "+uid+" from team "+t.Name+" via API", nil, nil)
	writeJSON(w, 200, deleted(uid))
}

// --- organizations ---

func validateOrg(o *store.Organization) string {
	o.Name = strings.TrimSpace(o.Name)
	if o.Name == "" {
		return "name is required"
	}
	if !validPeriod(o.BudgetPeriod) {
		return "invalid budget_period"
	}
	return ""
}

func (h *H) listOrgs(w http.ResponseWriter, r *http.Request) {
	orgs, err := h.d.Store.ListOrgs(r.Context())
	if err != nil {
		storeErr(w, err, "organizations")
		return
	}
	writeJSON(w, 200, list(orgs))
}

func (h *H) getOrg(w http.ResponseWriter, r *http.Request) {
	o, err := h.d.Store.GetOrg(r.Context(), param(r, "id"))
	if err != nil {
		storeErr(w, err, "organization")
		return
	}
	writeJSON(w, 200, o)
}

func (h *H) createOrg(w http.ResponseWriter, r *http.Request) {
	var o store.Organization
	if !decode(w, r, &o) {
		return
	}
	if msg := validateOrg(&o); msg != "" {
		badRequest(w, "%s", msg)
		return
	}
	created, err := h.d.Store.CreateOrg(r.Context(), o)
	if err != nil {
		storeErr(w, err, "organization")
		return
	}
	h.d.Changed()
	h.d.Audit(r, "create", "org", created.ID, "Created organization "+created.Name+" via API", nil, created)
	writeJSON(w, 201, created)
}

func (h *H) updateOrg(w http.ResponseWriter, r *http.Request) {
	o, err := h.d.Store.GetOrg(r.Context(), param(r, "id"))
	if err != nil {
		storeErr(w, err, "organization")
		return
	}
	before := o
	if !decode(w, r, &o) {
		return
	}
	o.ID, o.Spend, o.CreatedAt = before.ID, before.Spend, before.CreatedAt
	if msg := validateOrg(&o); msg != "" {
		badRequest(w, "%s", msg)
		return
	}
	if err := h.d.Store.UpdateOrg(r.Context(), o); err != nil {
		storeErr(w, err, "organization")
		return
	}
	h.d.Changed()
	h.d.Audit(r, "update", "org", o.ID, "Updated organization "+o.Name+" via API", before, o)
	o, _ = h.d.Store.GetOrg(r.Context(), o.ID)
	writeJSON(w, 200, o)
}

func (h *H) deleteOrg(w http.ResponseWriter, r *http.Request) {
	o, err := h.d.Store.GetOrg(r.Context(), param(r, "id"))
	if err != nil {
		storeErr(w, err, "organization")
		return
	}
	if err := h.d.Store.DeleteOrg(r.Context(), o.ID); err != nil {
		storeErr(w, err, "organization")
		return
	}
	h.d.Changed()
	h.d.Audit(r, "delete", "org", o.ID, "Deleted organization "+o.Name+" via API", o, nil)
	writeJSON(w, 200, deleted(o.ID))
}
