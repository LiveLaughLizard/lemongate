// Package ui is the server-rendered admin console framework: template rendering,
// page chrome, session middleware and form helpers. Feature areas live in
// sub-packages (internal/ui/<area>) and mount their own routes.
package ui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"sync"

	"lemongate/internal/auth"
	"lemongate/internal/settings"
)

// Renderer parses template sets. A set named "area/page" contains layouts, components,
// pages/<area>/_*.html (shared partials) and pages/<area>/<page>.html. A set named
// "area" contains only the shared partials (used for HTMX fragments).
type Renderer struct {
	fs      fs.FS
	dev     bool
	mu      sync.Mutex
	cache   map[string]*template.Template
	Version string
}

func NewRenderer(assets fs.FS, dev bool) *Renderer {
	return &Renderer{fs: assets, dev: dev, cache: map[string]*template.Template{}}
}

func (r *Renderer) Assets() fs.FS { return r.fs }

func (r *Renderer) set(name string) (*template.Template, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t, ok := r.cache[name]; ok && !r.dev {
		return t, nil
	}
	area, page, _ := strings.Cut(name, "/")
	patterns := []string{"templates/layouts/*.html", "templates/components/*.html", path.Join("templates/pages", area, "_*.html")}
	if page != "" {
		patterns = append(patterns, path.Join("templates/pages", area, page+".html"))
	}
	t := template.New("root").Funcs(r.funcs())
	for _, pattern := range patterns {
		files, err := fs.Glob(r.fs, pattern)
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			b, err := fs.ReadFile(r.fs, f)
			if err != nil {
				return nil, err
			}
			if _, err := t.New(f).Parse(string(b)); err != nil {
				return nil, fmt.Errorf("parse %s: %w", f, err)
			}
		}
	}
	if page != "" && t.Lookup("content") == nil {
		return nil, fmt.Errorf("page %s does not exist or defines no \"content\" template", name)
	}
	r.cache[name] = t
	return t, nil
}

// Exec renders a named template from a set ("area" or "area/page").
func (r *Renderer) Exec(w http.ResponseWriter, status int, set, name string, data any) {
	area := set
	t, err := r.set(set)
	if err != nil {
		slog.Error("template set", "area", area, "err", err)
		http.Error(w, "template error: "+err.Error(), 500)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, name, data); err != nil {
		slog.Error("template exec", "area", area, "name", name, "err", err)
		http.Error(w, "template error: "+err.Error(), 500)
		return
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// Page is the data passed to every full-page template.
type Page struct {
	Title    string
	Subtitle string
	Section  string // active nav key
	P        *auth.Principal
	CSRF     string
	Brand    settings.Branding
	Nav      []NavGroup
	Crumbs   []Crumb
	Data     any
	Version  string
	Features Features
}

type Crumb struct{ Label, Href string }

// Features toggles optional UI affordances.
type Features struct {
	SSO      bool
	SSOLabel string
	SMTP     bool
}

// Render renders a full page ("area/page") using the "app" layout. The page file must
// define "content". section selects the highlighted navigation item.
func (d *Deps) Render(w http.ResponseWriter, r *http.Request, page, section, title string, data any, crumbs ...Crumb) {
	p := auth.FromContext(r.Context())
	pg := Page{Title: title, Section: section, P: p, Brand: d.Settings.Current().Branding, Nav: NavFor(p),
		Data: data, Version: d.R.Version, Features: d.Features, Crumbs: crumbs}
	if p != nil {
		pg.CSRF = p.SessionCSRF
	}
	d.R.Exec(w, http.StatusOK, page, "app", pg)
}

// Partial renders one named template from the area's shared partials (pages/<area>/_*.html),
// without layout, e.g. for HTMX swaps.
// Data is wrapped as Page so partials can use .P, .CSRF and .Data uniformly.
func (d *Deps) Partial(w http.ResponseWriter, r *http.Request, status int, area, name string, data any) {
	p := auth.FromContext(r.Context())
	pg := Page{P: p, Data: data, Brand: d.Settings.Current().Branding, Features: d.Features}
	if p != nil {
		pg.CSRF = p.SessionCSRF
	}
	d.R.Exec(w, status, area, name, pg)
}

// --- HTMX response helpers ---

// IsHTMX reports whether the request came from htmx.
func IsHTMX(r *http.Request) bool { return r.Header.Get("HX-Request") == "true" }

// Trigger adds client-side events to the response (merged into HX-Trigger).
func Trigger(w http.ResponseWriter, events map[string]any) {
	existing := map[string]any{}
	if v := w.Header().Get("HX-Trigger"); v != "" {
		_ = json.Unmarshal([]byte(v), &existing)
	}
	for k, v := range events {
		existing[k] = v
	}
	b, _ := json.Marshal(existing)
	w.Header().Set("HX-Trigger", string(b))
}

// Toast shows a notification. kind: success | error | info | warning.
func Toast(w http.ResponseWriter, kind, msg string) {
	Trigger(w, map[string]any{"toast": map[string]string{"kind": kind, "message": msg}})
}

// CloseModal closes the global modal dialog.
func CloseModal(w http.ResponseWriter) { Trigger(w, map[string]any{"close-modal": true}) }

// Refresh fires a named event that lists listen for (hx-trigger="<name> from:body").
func Refresh(w http.ResponseWriter, event string) { Trigger(w, map[string]any{event: true}) }

// Redirect navigates the browser, HTMX-aware.
func Redirect(w http.ResponseWriter, r *http.Request, url string) {
	if IsHTMX(r) {
		w.Header().Set("HX-Redirect", url)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, url, http.StatusSeeOther)
}

// Done ends a successful mutation: toast, close the modal, fire refresh events.
func Done(w http.ResponseWriter, msg string, refresh ...string) {
	Toast(w, "success", msg)
	CloseModal(w)
	for _, e := range refresh {
		Refresh(w, e)
	}
	w.WriteHeader(http.StatusNoContent)
}

// Fail reports an error as a toast without swapping content.
func Fail(w http.ResponseWriter, status int, msg string) {
	Toast(w, "error", msg)
	w.Header().Set("HX-Reswap", "none")
	w.WriteHeader(status)
}
