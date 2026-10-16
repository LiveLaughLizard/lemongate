// Package endusers manages end users: the customer identifiers callers pass in the
// `user` field of requests. Admins can label them, give them budgets and block them.
package endusers

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/go-chi/chi/v5"

	"lemongate/internal/analytics"
	"lemongate/internal/store"
	"lemongate/internal/ui"
)

const area = "endusers"

type H struct{ d *ui.Deps }

func Mount(r chi.Router, d *ui.Deps) {
	h := &H{d}
	r.Group(func(r chi.Router) {
		r.Use(ui.AdminWrites)
		r.Get("/ui/end-users", h.index)
		r.Get("/ui/end-users/table", h.table)
		r.Get("/ui/end-users/new", h.newForm)
		r.Post("/ui/end-users", h.create)
		r.Get("/ui/end-users/{id}/edit", h.editForm)
		r.Get("/ui/end-users/{id}/usage", h.usage)
		r.Post("/ui/end-users/{id}", h.update)
		r.Post("/ui/end-users/{id}/block", h.setBlocked(true))
		r.Post("/ui/end-users/{id}/unblock", h.setBlocked(false))
		r.Post("/ui/end-users/{id}/reset-spend", h.resetSpend)
		r.Post("/ui/end-users/{id}/delete", h.delete)
	})
}

type indexData struct {
	Stats    store.EndUserStats
	Q        string
	Tracking bool
}

func (h *H) index(w http.ResponseWriter, r *http.Request) {
	st, _ := h.d.Store.GetEndUserStats(r.Context())
	h.d.Render(w, r, "endusers/index", "endusers", "End users", indexData{Stats: st, Q: r.URL.Query().Get("q"),
		Tracking: h.d.Settings.Current().General.TrackEndUsers})
}

type tableData struct {
	Users    []store.EndUser
	Filtered bool
}

func (h *H) table(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.EndUserFilter{Search: q.Get("q"), Status: q.Get("status"), Sort: q.Get("sort")}
	list, err := h.d.Store.FilterEndUsers(r.Context(), f)
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Partial(w, r, 200, area, "endusers-table", tableData{Users: list, Filtered: f.Search != "" || f.Status != ""})
}

type formData struct {
	User  store.EndUser
	IsNew bool
	Error string
}

func (h *H) newForm(w http.ResponseWriter, r *http.Request) {
	h.d.Partial(w, r, 200, area, "enduser-form", formData{IsNew: true})
}

func bind(r *http.Request, e *store.EndUser) {
	_ = r.ParseForm()
	e.Alias = ui.FormStr(r, "alias")
	e.MaxBudget = ui.FormFloatPtr(r, "max_budget")
	e.BudgetPeriod = ui.FormStr(r, "budget_period")
	e.Blocked = ui.FormBool(r, "blocked")
}

func (h *H) create(w http.ResponseWriter, r *http.Request) {
	var e store.EndUser
	bind(r, &e)
	e.ID = ui.FormStr(r, "id")
	fail := func(msg string) {
		h.d.Partial(w, r, 422, area, "enduser-form", formData{User: e, IsNew: true, Error: msg})
	}
	if e.ID == "" {
		fail("An identifier is required — it must match the `user` field your application sends.")
		return
	}
	if len(e.ID) > 256 {
		fail("Identifier is too long (max 256 characters).")
		return
	}
	if err := h.d.Store.CreateEndUser(r.Context(), e); err != nil {
		if errors.Is(err, store.ErrConflict) {
			fail("An end user with that identifier already exists.")
		} else {
			fail(err.Error())
		}
		return
	}
	h.d.Changed()
	h.d.Audit(r, "create", "end_user", e.ID, "Registered end user "+e.ID, nil, e)
	ui.Done(w, "End user added", "refresh-endusers")
}

func (h *H) load(w http.ResponseWriter, r *http.Request) (store.EndUser, bool) {
	id, _ := url.PathUnescape(chi.URLParam(r, "id"))
	e, err := h.d.Store.GetEndUser(r.Context(), id)
	if err != nil {
		ui.Fail(w, 404, "End user not found")
		return e, false
	}
	return e, true
}

func (h *H) editForm(w http.ResponseWriter, r *http.Request) {
	e, ok := h.load(w, r)
	if !ok {
		return
	}
	h.d.Partial(w, r, 200, area, "enduser-form", formData{User: e})
}

func (h *H) update(w http.ResponseWriter, r *http.Request) {
	e, ok := h.load(w, r)
	if !ok {
		return
	}
	before := e
	bind(r, &e)
	if err := h.d.Store.UpdateEndUser(r.Context(), e); err != nil {
		h.d.Partial(w, r, 422, area, "enduser-form", formData{User: e, Error: err.Error()})
		return
	}
	h.d.Changed()
	h.d.Audit(r, "update", "end_user", e.ID, "Updated end user "+e.ID, before, e)
	ui.Done(w, "End user updated", "refresh-endusers")
}

func (h *H) setBlocked(blocked bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		e, ok := h.load(w, r)
		if !ok {
			return
		}
		if err := h.d.Store.SetEndUserBlocked(r.Context(), e.ID, blocked); err != nil {
			ui.Fail(w, 500, err.Error())
			return
		}
		h.d.Changed()
		action, verb := "unblock", "Unblocked"
		if blocked {
			action, verb = "block", "Blocked"
		}
		h.d.Audit(r, action, "end_user", e.ID, verb+" end user "+e.ID, nil, nil)
		ui.Done(w, verb+" "+e.ID, "refresh-endusers")
	}
}

func (h *H) resetSpend(w http.ResponseWriter, r *http.Request) {
	e, ok := h.load(w, r)
	if !ok {
		return
	}
	_ = h.d.Store.ResetEndUserSpend(r.Context(), e.ID)
	h.d.Changed()
	h.d.Audit(r, "reset_spend", "end_user", e.ID, "Reset spend for end user "+e.ID, map[string]any{"spend": e.Spend}, nil)
	ui.Done(w, "Spend reset", "refresh-endusers")
}

func (h *H) delete(w http.ResponseWriter, r *http.Request) {
	e, ok := h.load(w, r)
	if !ok {
		return
	}
	if err := h.d.Store.DeleteEndUser(r.Context(), e.ID); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Changed()
	h.d.Audit(r, "delete", "end_user", e.ID, "Deleted end user "+e.ID, e, nil)
	ui.Done(w, "End user deleted", "refresh-endusers")
}

type usageData struct {
	User    store.EndUser
	Days    int
	Totals  analytics.Totals
	Chart   analytics.ChartSpec
	ByModel []analytics.Row
}

// usage renders the modal with an end user's recent traffic.
func (h *H) usage(w http.ResponseWriter, r *http.Request) {
	e, ok := h.load(w, r)
	if !ok {
		return
	}
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days <= 0 || days > 365 {
		days = 30
	}
	f := analytics.LastDays(days)
	f.EndUser = e.ID
	ud := usageData{User: e, Days: days}
	ud.Totals, _ = analytics.GetTotals(r.Context(), h.d.Store.Pool, f)
	pts, _ := analytics.Daily(r.Context(), h.d.Store.Pool, f)
	ud.Chart = analytics.DailyChart(pts, "bar", "money", map[string]func(analytics.DayPoint) float64{
		"Spend": func(p analytics.DayPoint) float64 { return p.Cost },
	}, "Spend")
	ud.ByModel, _ = analytics.Breakdown(r.Context(), h.d.Store.Pool, f, "model", 6)
	h.d.Partial(w, r, 200, area, "enduser-usage", ud)
}
