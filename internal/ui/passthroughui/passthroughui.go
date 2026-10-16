// Package passthroughui is the console area for pass-through routes.
package passthroughui

import (
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"

	"lemongate/internal/auth"
	"lemongate/internal/passthrough"
	"lemongate/internal/store"
	"lemongate/internal/ui"
)

const area = "passthrough"

type H struct {
	d  *ui.Deps
	pt *passthrough.Router
}

// Mount registers routes for this area on the session-protected router.
func Mount(r chi.Router, d *ui.Deps, pt *passthrough.Router) {
	h := &H{d: d, pt: pt}
	r.Group(func(r chi.Router) {
		r.Use(ui.AdminWrites)
		r.Get("/ui/passthrough", h.index)
		r.Get("/ui/passthrough/table", h.table)
		r.Get("/ui/passthrough/calls", h.calls)
		r.Get("/ui/passthrough/new", h.newForm)
		r.Post("/ui/passthrough", h.create)
		r.Get("/ui/passthrough/{id}/edit", h.editForm)
		r.Get("/ui/passthrough/{id}/usage", h.usage)
		r.Post("/ui/passthrough/{id}", h.update)
		r.Post("/ui/passthrough/{id}/toggle", h.toggle)
		r.Post("/ui/passthrough/{id}/delete", h.delete)
	})
}

type indexData struct {
	CanEdit bool
	Routes  []passthrough.Route
}

func (h *H) index(w http.ResponseWriter, r *http.Request) {
	routes, _ := h.pt.List(r.Context())
	h.d.Render(w, r, "passthrough/index", "passthrough", "Pass-through routes",
		indexData{CanEdit: auth.FromContext(r.Context()).IsAdmin(), Routes: routes})
}

type row struct {
	passthrough.Route
	URL   string
	Stats passthrough.RouteStats
}

type tableData struct {
	Rows    []row
	CanEdit bool
}

func (h *H) publicURL(name string) string { return h.d.Cfg.BaseURL + "/pt/" + name + "/" }

func (h *H) table(w http.ResponseWriter, r *http.Request) {
	routes, err := h.pt.List(r.Context())
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	stats := h.pt.Stats24h(r.Context())
	td := tableData{CanEdit: auth.FromContext(r.Context()).IsAdmin()}
	for _, rt := range routes {
		td.Rows = append(td.Rows, row{Route: rt, URL: h.publicURL(rt.Name), Stats: stats[rt.Name]})
	}
	h.d.Partial(w, r, 200, area, "routes-table", td)
}

type callsData struct {
	Calls []passthrough.Call
}

func (h *H) calls(w http.ResponseWriter, r *http.Request) {
	calls, err := h.pt.RecentCalls(r.Context(), r.URL.Query().Get("route"), 50)
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Partial(w, r, 200, area, "calls-table", callsData{Calls: calls})
}

// --- form ---

type formData struct {
	R           passthrough.Route
	IsNew       bool
	Error       string
	Credentials []store.Credential
	Headers     string
	BaseURL     string
}

func (h *H) form(r *http.Request, rt passthrough.Route, isNew bool, errMsg string) formData {
	creds, _ := h.d.Store.ListCredentials(r.Context())
	var hdr []string
	for k, v := range rt.ExtraHeaders {
		hdr = append(hdr, k+": "+v)
	}
	sort.Strings(hdr)
	return formData{R: rt, IsNew: isNew, Error: errMsg, Credentials: creds, Headers: strings.Join(hdr, "\n"), BaseURL: h.d.Cfg.BaseURL}
}

func (h *H) newForm(w http.ResponseWriter, r *http.Request) {
	rt := passthrough.Route{AuthHeader: "Authorization", AuthPrefix: "Bearer ", RequireKey: true, Enabled: true}
	h.d.Partial(w, r, 200, area, "route-form", h.form(r, rt, true, ""))
}

func bind(r *http.Request, rt *passthrough.Route) {
	_ = r.ParseForm()
	rt.Name = ui.FormStr(r, "name")
	rt.TargetURL = ui.FormStr(r, "target_url")
	rt.CredentialID = store.NullIfEmpty(ui.FormStr(r, "credential_id"))
	rt.AuthHeader = ui.FormStr(r, "auth_header")
	// The prefix is significant whitespace ("Bearer "), so it is not trimmed.
	rt.AuthPrefix = r.FormValue("auth_prefix")
	rt.ExtraHeaders = ui.FormStringMap(r, "extra_headers")
	rt.RequireKey = ui.FormBool(r, "require_key")
	rt.CostPerRequest = ui.FormFloat(r, "cost_per_request")
	rt.Description = ui.FormStr(r, "description")
	rt.Enabled = ui.FormBool(r, "enabled")
}

func (h *H) create(w http.ResponseWriter, r *http.Request) {
	var rt passthrough.Route
	bind(r, &rt)
	if err := h.pt.Save(r.Context(), &rt); err != nil {
		h.d.Partial(w, r, 422, area, "route-form", h.form(r, rt, true, err.Error()))
		return
	}
	h.d.Audit(r, "create", "passthrough_route", rt.ID, "Created pass-through route "+rt.Name, nil, rt)
	ui.Toast(w, "success", "Route "+rt.Name+" created")
	ui.Refresh(w, "refresh-routes")
	h.usageModal(w, r, rt, true)
}

func (h *H) load(w http.ResponseWriter, r *http.Request) (passthrough.Route, bool) {
	rt, err := h.pt.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		if errors.Is(err, passthrough.ErrNotFound) {
			ui.Fail(w, 404, "Route not found")
		} else {
			ui.Fail(w, 500, err.Error())
		}
		return rt, false
	}
	return rt, true
}

func (h *H) editForm(w http.ResponseWriter, r *http.Request) {
	rt, ok := h.load(w, r)
	if !ok {
		return
	}
	h.d.Partial(w, r, 200, area, "route-form", h.form(r, rt, false, ""))
}

func (h *H) update(w http.ResponseWriter, r *http.Request) {
	rt, ok := h.load(w, r)
	if !ok {
		return
	}
	before := rt
	bind(r, &rt)
	if err := h.pt.Save(r.Context(), &rt); err != nil {
		h.d.Partial(w, r, 422, area, "route-form", h.form(r, rt, false, err.Error()))
		return
	}
	h.d.Audit(r, "update", "passthrough_route", rt.ID, "Updated pass-through route "+rt.Name, before, rt)
	ui.Done(w, "Route saved", "refresh-routes")
}

func (h *H) toggle(w http.ResponseWriter, r *http.Request) {
	rt, ok := h.load(w, r)
	if !ok {
		return
	}
	if err := h.pt.SetEnabled(r.Context(), rt.ID, !rt.Enabled); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	verb := "Enabled"
	if rt.Enabled {
		verb = "Disabled"
	}
	h.d.Audit(r, strings.ToLower(verb[:len(verb)-1]), "passthrough_route", rt.ID, verb+" pass-through route "+rt.Name, nil, nil)
	ui.Toast(w, "success", verb+" "+rt.Name)
	ui.Refresh(w, "refresh-routes")
	w.WriteHeader(http.StatusNoContent)
}

func (h *H) delete(w http.ResponseWriter, r *http.Request) {
	rt, ok := h.load(w, r)
	if !ok {
		return
	}
	if err := h.pt.Delete(r.Context(), rt.ID); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Audit(r, "delete", "passthrough_route", rt.ID, "Deleted pass-through route "+rt.Name, rt, nil)
	ui.Done(w, "Route "+rt.Name+" deleted", "refresh-routes")
}

// --- usage modal ---

type usageData struct {
	R       passthrough.Route
	URL     string
	Created bool
}

func (h *H) usage(w http.ResponseWriter, r *http.Request) {
	rt, ok := h.load(w, r)
	if !ok {
		return
	}
	h.usageModal(w, r, rt, false)
}

func (h *H) usageModal(w http.ResponseWriter, r *http.Request, rt passthrough.Route, created bool) {
	h.d.Partial(w, r, 200, area, "route-usage", usageData{R: rt, URL: h.publicURL(rt.Name), Created: created})
}
