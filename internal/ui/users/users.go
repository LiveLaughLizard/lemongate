// Package users is the console user management area (admins) and the
// self-service profile page (every signed-in user).
package users

import (
	"context"
	"encoding/csv"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"lemongate/internal/analytics"
	"lemongate/internal/auth"
	"lemongate/internal/store"
	"lemongate/internal/ui"
)

const area = "users"

const inviteTTL = 7 * 24 * time.Hour

type H struct{ d *ui.Deps }

func Mount(r chi.Router, d *ui.Deps) {
	h := &H{d}
	r.Group(func(r chi.Router) {
		r.Use(ui.AdminWrites)
		r.Get("/ui/users", h.index)
		r.Get("/ui/users/table", h.table)
		r.Get("/ui/users/new", h.newForm)
		r.Post("/ui/users", h.create)
		r.Get("/ui/users/bulk", h.bulkForm)
		r.Post("/ui/users/bulk", h.bulkCreate)
		r.Get("/ui/users/{id}", h.show)
		r.Get("/ui/users/{id}/edit", h.editForm)
		r.Post("/ui/users/{id}", h.update)
		r.Post("/ui/users/{id}/block", h.setBlocked(true))
		r.Post("/ui/users/{id}/unblock", h.setBlocked(false))
		r.Post("/ui/users/{id}/invite", h.resetInvite)
		r.Post("/ui/users/{id}/revoke-sessions", h.revokeSessions)
		r.Post("/ui/users/{id}/reset-spend", h.resetSpend)
		r.Post("/ui/users/{id}/delete", h.delete)
	})
	r.Get("/ui/profile", h.profile)
	r.Post("/ui/profile", h.updateProfile)
	r.Post("/ui/profile/password", h.changePassword)
}

// RoleOption describes an application role for pickers.
type RoleOption struct{ Value, Label, Hint string }

var roleOptions = []RoleOption{
	{auth.RoleAdmin, "Admin", "Full access to every setting and entity"},
	{auth.RoleAdminViewer, "Admin (read-only)", "Can view everything, change nothing"},
	{auth.RoleMember, "Member", "Own keys, own usage and their teams"},
	{auth.RoleMemberViewer, "Member (read-only)", "Can view their own keys and usage"},
}

func validRole(r string) bool { return slices.Contains(auth.Roles, r) }

// --- listing ---

type indexData struct {
	Roles     []RoleOption
	CanCreate bool
	Role      string
}

func (h *H) index(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	h.d.Render(w, r, "users/index", "users", "Users", indexData{Roles: roleOptions, CanCreate: p.IsAdmin(), Role: r.URL.Query().Get("role")})
}

type tableData struct {
	Users  []store.User
	SelfID string
	Counts map[string]int
	Total  int
}

func (h *H) table(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	q := r.URL.Query()
	users, err := h.d.Store.ListUsers(r.Context(), q.Get("q"), q.Get("role"))
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	switch q.Get("status") {
	case "blocked":
		users = slices.DeleteFunc(users, func(u store.User) bool { return !u.Blocked })
	case "active":
		users = slices.DeleteFunc(users, func(u store.User) bool { return u.Blocked })
	}
	h.d.Partial(w, r, 200, area, "users-table", tableData{Users: users, SelfID: p.UserID(), Total: len(users)})
}

// --- create / edit ---

type formData struct {
	User   store.User
	IsNew  bool
	Error  string
	Roles  []RoleOption
	Orgs   []store.Organization
	Models []string
	Groups []string
	Access string // invite | password | none
	IsSelf bool
	SMTP   bool
}

func (h *H) form(ctx context.Context, u store.User, isNew bool) formData {
	fd := formData{User: u, IsNew: isNew, Roles: roleOptions, Models: h.d.Registry.AllModelNames(),
		Groups: h.d.Registry.AccessGroupNames(), Access: "invite", SMTP: h.d.Features.SMTP}
	fd.Orgs, _ = h.d.Store.ListOrgs(ctx)
	return fd
}

func (h *H) newForm(w http.ResponseWriter, r *http.Request) {
	h.d.Partial(w, r, 200, area, "user-form", h.form(r.Context(), store.User{Role: auth.RoleMember}, true))
}

func bind(r *http.Request, u *store.User) error {
	_ = r.ParseForm()
	u.Email = strings.ToLower(ui.FormStr(r, "email"))
	if !strings.Contains(u.Email, "@") || strings.ContainsAny(u.Email, " ,;") {
		return errors.New("Enter a valid email address")
	}
	u.Name = ui.FormStr(r, "name")
	if role := ui.FormStr(r, "role"); validRole(role) {
		u.Role = role
	} else {
		return errors.New("Choose a role")
	}
	u.OrgID = store.NullIfEmpty(ui.FormStr(r, "org_id"))
	u.Models = ui.FormList(r, "models")
	u.MaxBudget = ui.FormFloatPtr(r, "max_budget")
	u.BudgetPeriod = ui.FormStr(r, "budget_period")
	u.RPMLimit, u.TPMLimit, u.MaxParallel = ui.FormIntPtr(r, "rpm_limit"), ui.FormIntPtr(r, "tpm_limit"), ui.FormIntPtr(r, "max_parallel")
	md, err := ui.FormJSONMap(r, "metadata")
	if err != nil {
		return errors.New("Metadata must be a JSON object")
	}
	u.Metadata = md
	return nil
}

func errText(err error) string {
	if errors.Is(err, store.ErrConflict) {
		return "A user with that email already exists."
	}
	return err.Error()
}

type inviteData struct {
	User    store.User
	Link    string
	Title   string
	Expires time.Time
}

func (h *H) newInvite(r *http.Request, u store.User) (inviteData, error) {
	p := auth.FromContext(r.Context())
	token := auth.RandomString(40)
	exp := time.Now().Add(inviteTTL)
	if err := h.d.Store.CreateInvite(r.Context(), auth.HashToken(token), u.ID, p.Label(), exp); err != nil {
		return inviteData{}, err
	}
	return inviteData{User: u, Link: strings.TrimRight(h.d.Cfg.BaseURL, "/") + "/ui/invite/" + token, Expires: exp}, nil
}

func (h *H) create(w http.ResponseWriter, r *http.Request) {
	u := store.User{}
	fail := func(msg string, access string) {
		fd := h.form(r.Context(), u, true)
		fd.Error, fd.Access = msg, access
		h.d.Partial(w, r, 422, area, "user-form", fd)
	}
	if err := bind(r, &u); err != nil {
		fail(err.Error(), ui.FormStr(r, "access"))
		return
	}
	access := ui.FormStr(r, "access")
	switch access {
	case "password":
		pw := r.FormValue("password")
		if len(pw) < 8 {
			fail("Initial password must be at least 8 characters.", access)
			return
		}
		hash, err := auth.HashPassword(pw)
		if err != nil {
			fail(err.Error(), access)
			return
		}
		u.PasswordHash = hash
	case "invite", "none":
	default:
		access = "invite"
	}
	created, err := h.d.Store.CreateUser(r.Context(), u)
	if err != nil {
		fail(errText(err), access)
		return
	}
	h.d.Changed()
	h.d.Audit(r, "create", "user", created.ID, "Created user "+created.Email, nil, created)
	if access != "invite" {
		ui.Done(w, "User "+created.Email+" created", "refresh-users")
		return
	}
	inv, err := h.newInvite(r, created)
	if err != nil {
		ui.Done(w, "User created, but the invite could not be generated: "+err.Error(), "refresh-users")
		return
	}
	inv.Title = "User created"
	ui.Toast(w, "success", "User "+created.Email+" created")
	ui.Refresh(w, "refresh-users")
	h.d.Partial(w, r, 200, area, "user-invite", inv)
}

func (h *H) load(w http.ResponseWriter, r *http.Request) (store.User, *auth.Principal, bool) {
	p := auth.FromContext(r.Context())
	u, err := h.d.Store.GetUser(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		if ui.IsHTMX(r) {
			ui.Fail(w, 404, "User not found")
		} else {
			http.NotFound(w, r)
		}
		return u, p, false
	}
	return u, p, true
}

func (h *H) editForm(w http.ResponseWriter, r *http.Request) {
	u, p, ok := h.load(w, r)
	if !ok {
		return
	}
	if !p.IsAdmin() {
		ui.Forbidden(w, r)
		return
	}
	fd := h.form(r.Context(), u, false)
	fd.IsSelf = u.ID == p.UserID()
	h.d.Partial(w, r, 200, area, "user-form", fd)
}

func (h *H) update(w http.ResponseWriter, r *http.Request) {
	u, p, ok := h.load(w, r)
	if !ok {
		return
	}
	before := u
	err := bind(r, &u)
	if err == nil && u.ID == p.UserID() && u.Role != auth.RoleAdmin {
		err = errors.New("You can't remove your own admin role.")
	}
	if err == nil {
		err = h.d.Store.UpdateUser(r.Context(), u)
	}
	if err != nil {
		fd := h.form(r.Context(), u, false)
		fd.Error, fd.IsSelf = errText(err), u.ID == p.UserID()
		h.d.Partial(w, r, 422, area, "user-form", fd)
		return
	}
	h.d.Changed()
	h.d.Audit(r, "update", "user", u.ID, "Updated user "+u.Email, before, u)
	ui.Done(w, "User updated", "refresh-users", "refresh-user")
}

func (h *H) setBlocked(blocked bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := h.load(w, r)
		if !ok {
			return
		}
		if u.ID == p.UserID() {
			ui.Fail(w, 400, "You can't block yourself.")
			return
		}
		if err := h.d.Store.SetUserBlocked(r.Context(), u.ID, blocked); err != nil {
			ui.Fail(w, 500, err.Error())
			return
		}
		verb, action := "Unblocked", "unblock"
		if blocked {
			verb, action = "Blocked", "block"
			_ = h.d.Store.DeleteUserSessions(r.Context(), u.ID)
		}
		h.d.Changed()
		h.d.Audit(r, action, "user", u.ID, verb+" user "+u.Email, nil, nil)
		ui.Done(w, verb+" "+u.Email, "refresh-users", "refresh-user")
	}
}

// resetInvite issues a fresh invite link the user can use to set a new password.
func (h *H) resetInvite(w http.ResponseWriter, r *http.Request) {
	u, _, ok := h.load(w, r)
	if !ok {
		return
	}
	_ = h.d.Store.RevokeUserInvites(r.Context(), u.ID)
	inv, err := h.newInvite(r, u)
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	inv.Title = "Password reset link"
	h.d.Audit(r, "reset_password", "user", u.ID, "Issued password reset link for "+u.Email, nil, nil)
	ui.Refresh(w, "refresh-user")
	h.d.Partial(w, r, 200, area, "user-invite", inv)
}

func (h *H) revokeSessions(w http.ResponseWriter, r *http.Request) {
	u, _, ok := h.load(w, r)
	if !ok {
		return
	}
	if err := h.d.Store.DeleteUserSessions(r.Context(), u.ID); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Audit(r, "revoke_sessions", "user", u.ID, "Signed out every session of "+u.Email, nil, nil)
	ui.Done(w, "All sessions of "+u.Email+" revoked", "refresh-user")
}

func (h *H) resetSpend(w http.ResponseWriter, r *http.Request) {
	u, _, ok := h.load(w, r)
	if !ok {
		return
	}
	if _, err := h.d.Store.Pool.Exec(r.Context(), `UPDATE users SET spend=0, updated_at=now() WHERE id=$1`, u.ID); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Changed()
	h.d.Audit(r, "reset_spend", "user", u.ID, "Reset spend for user "+u.Email, map[string]any{"spend": u.Spend}, nil)
	ui.Done(w, "Spend reset", "refresh-users", "refresh-user")
}

func (h *H) delete(w http.ResponseWriter, r *http.Request) {
	u, p, ok := h.load(w, r)
	if !ok {
		return
	}
	if u.ID == p.UserID() {
		ui.Fail(w, 400, "You can't delete your own account.")
		return
	}
	if err := h.d.Store.DeleteUser(r.Context(), u.ID); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Changed()
	h.d.Audit(r, "delete", "user", u.ID, "Deleted user "+u.Email, u, nil)
	if r.URL.Query().Get("from") == "detail" {
		ui.Toast(w, "success", "User deleted")
		ui.Redirect(w, r, "/ui/users")
		return
	}
	ui.Done(w, "User deleted", "refresh-users")
}

// --- bulk create ---

type bulkData struct {
	CSV     string
	Role    string
	Error   string
	Roles   []RoleOption
	Results []bulkResult
	Created int
}

type bulkResult struct {
	Email, Name, Role, Link, Error string
}

func (h *H) bulkForm(w http.ResponseWriter, r *http.Request) {
	if !auth.FromContext(r.Context()).IsAdmin() {
		ui.Forbidden(w, r)
		return
	}
	h.d.Partial(w, r, 200, area, "user-bulk", bulkData{Roles: roleOptions, Role: auth.RoleMember})
}

func (h *H) bulkCreate(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	bd := bulkData{CSV: r.FormValue("csv"), Role: ui.FormStr(r, "role"), Roles: roleOptions}
	if !validRole(bd.Role) {
		bd.Role = auth.RoleMember
	}
	cr := csv.NewReader(strings.NewReader(bd.CSV))
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true
	var rows [][]string
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			bd.Error = "Could not parse CSV: " + err.Error()
			h.d.Partial(w, r, 422, area, "user-bulk", bd)
			return
		}
		if len(rec) == 0 || strings.TrimSpace(rec[0]) == "" || strings.EqualFold(strings.TrimSpace(rec[0]), "email") {
			continue
		}
		rows = append(rows, rec)
	}
	if len(rows) == 0 {
		bd.Error = "Paste at least one line in the form: email,name,role"
		h.d.Partial(w, r, 422, area, "user-bulk", bd)
		return
	}
	if len(rows) > 500 {
		bd.Error = "At most 500 users can be created at once."
		h.d.Partial(w, r, 422, area, "user-bulk", bd)
		return
	}
	for _, rec := range rows {
		res := bulkResult{Email: strings.ToLower(strings.TrimSpace(rec[0])), Role: bd.Role}
		if len(rec) > 1 {
			res.Name = strings.TrimSpace(rec[1])
		}
		if len(rec) > 2 && strings.TrimSpace(rec[2]) != "" {
			res.Role = strings.TrimSpace(rec[2])
		}
		switch {
		case !strings.Contains(res.Email, "@"):
			res.Error = "invalid email"
		case !validRole(res.Role):
			res.Error = "unknown role " + strconv.Quote(res.Role)
		}
		if res.Error == "" {
			u, err := h.d.Store.CreateUser(r.Context(), store.User{Email: res.Email, Name: res.Name, Role: res.Role})
			if err != nil {
				res.Error = errText(err)
			} else {
				bd.Created++
				h.d.Audit(r, "create", "user", u.ID, "Created user "+u.Email+" (bulk)", nil, u)
				if inv, err := h.newInvite(r, u); err == nil {
					res.Link = inv.Link
				}
			}
		}
		bd.Results = append(bd.Results, res)
	}
	h.d.Changed()
	ui.Toast(w, "success", strconv.Itoa(bd.Created)+" users created")
	ui.Refresh(w, "refresh-users")
	h.d.Partial(w, r, 200, area, "user-bulk-result", bd)
}

// --- detail ---

type showData struct {
	User        store.User
	IsAdmin     bool
	IsSelf      bool
	Memberships []store.TeamMember
	Keys        []store.Key
	Access      store.UserAccessInfo
	Totals      analytics.Totals
	Chart       analytics.ChartSpec
	ByModel     []analytics.Row
	Allowed     []string
	AllModels   bool
	RPM, TPM    float64
	InFlight    int
	Days        int
	Profile     bool
	HasPassword bool
}

func (h *H) detail(r *http.Request, u store.User, days int) showData {
	ctx := r.Context()
	p := auth.FromContext(ctx)
	sd := showData{User: u, IsAdmin: p.IsAdmin(), IsSelf: u.ID == p.UserID(), Days: days, HasPassword: u.PasswordHash != ""}
	sd.Memberships, _ = h.d.Store.MembershipsForUser(ctx, u.ID)
	sd.Keys, _ = h.d.Store.ListKeys(ctx, store.KeyFilter{UserID: u.ID})
	sd.Access = h.d.Store.GetUserAccessInfo(ctx, u.ID)
	f := analytics.LastDays(days)
	f.UserID = u.ID
	sd.Totals, _ = analytics.GetTotals(ctx, h.d.Store.Pool, f)
	pts, _ := analytics.Daily(ctx, h.d.Store.Pool, f)
	sd.Chart = analytics.DailyChart(pts, "bar", "money", map[string]func(analytics.DayPoint) float64{
		"Spend": func(p analytics.DayPoint) float64 { return p.Cost },
	}, "Spend")
	sd.ByModel, _ = analytics.Breakdown(ctx, h.d.Store.Pool, f, "model", 6)
	sd.RPM, sd.TPM, sd.InFlight = h.d.Limiter.Usage("user:" + u.ID)
	up := &auth.Principal{Kind: "key", User: &u}
	if u.OrgID != nil {
		if o, err := h.d.Store.GetOrg(ctx, *u.OrgID); err == nil {
			up.Org = &o
		}
	}
	if u.Role == auth.RoleAdmin {
		sd.Allowed = nil
	} else {
		sd.Allowed = up.AllowedModels(h.d.Registry)
		if sd.Allowed != nil {
			slices.Sort(sd.Allowed)
			sd.Allowed = slices.Compact(sd.Allowed)
		}
	}
	sd.AllModels = sd.Allowed == nil
	return sd
}

func days(r *http.Request) int {
	d, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if d <= 0 || d > 365 {
		d = 30
	}
	return d
}

func (h *H) show(w http.ResponseWriter, r *http.Request) {
	u, _, ok := h.load(w, r)
	if !ok {
		return
	}
	sd := h.detail(r, u, days(r))
	if r.Header.Get("HX-Target") == "user-detail" {
		h.d.Partial(w, r, 200, area, "user-detail", sd)
		return
	}
	h.d.Render(w, r, "users/show", "users", u.DisplayName(), sd, ui.Crumb{Label: "Users", Href: "/ui/users"})
}

// --- profile (self-service) ---

func (h *H) profile(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	if p.User == nil {
		http.Redirect(w, r, "/ui", http.StatusSeeOther)
		return
	}
	u, err := h.d.Store.GetUser(r.Context(), p.User.ID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	sd := h.detail(r, u, days(r))
	sd.Profile = true
	h.d.Render(w, r, "users/profile", "", "My profile", sd)
}

func (h *H) updateProfile(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	if p.User == nil {
		ui.Forbidden(w, r)
		return
	}
	_ = r.ParseForm()
	name := ui.FormStr(r, "name")
	if len(name) > 120 {
		ui.Fail(w, 422, "Name is too long")
		return
	}
	if err := h.d.Store.UpdateUserName(r.Context(), p.User.ID, name); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Changed()
	h.d.Audit(r, "update", "user", p.User.ID, "Updated own profile", map[string]any{"name": p.User.Name}, map[string]any{"name": name})
	ui.Toast(w, "success", "Profile saved")
	w.WriteHeader(http.StatusNoContent)
}

func (h *H) changePassword(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	if p.User == nil {
		ui.Forbidden(w, r)
		return
	}
	u, err := h.d.Store.GetUser(r.Context(), p.User.ID)
	if err != nil {
		ui.Fail(w, 404, "User not found")
		return
	}
	_ = r.ParseForm()
	cur, next, confirm := r.FormValue("current"), r.FormValue("password"), r.FormValue("confirm")
	switch {
	case u.PasswordHash == "" && u.SSOSubject != nil:
		// A local password would keep working after the identity provider disables the account.
		ui.Fail(w, 422, "Your account signs in with single sign-on and can't have a password.")
		return
	case u.PasswordHash != "" && !auth.CheckPassword(u.PasswordHash, cur):
		ui.Fail(w, 422, "Your current password is incorrect.")
		return
	case len(next) < 8:
		ui.Fail(w, 422, "The new password must be at least 8 characters.")
		return
	case next != confirm:
		ui.Fail(w, 422, "The new passwords don't match.")
		return
	}
	hash, err := auth.HashPassword(next)
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	if err := h.d.Store.SetUserPassword(r.Context(), u.ID, hash); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	if c, err := r.Cookie(ui.SessionCookie); err == nil {
		_ = h.d.Store.DeleteOtherUserSessions(r.Context(), u.ID, auth.HashToken(c.Value))
	}
	h.d.Audit(r, "change_password", "user", u.ID, "Changed own password", nil, nil)
	ui.Toast(w, "success", "Password updated")
	ui.Refresh(w, "password-changed")
	w.WriteHeader(http.StatusNoContent)
}
