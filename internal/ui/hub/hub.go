// Package hub is the model catalog: every model the signed-in principal may call,
// with pricing, limits, health and ready-to-copy request snippets.
package hub

import (
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"

	"lemongate/internal/analytics"
	"lemongate/internal/auth"
	"lemongate/internal/routing"
	"lemongate/internal/ui"
)

const area = "hub"

type H struct{ d *ui.Deps }

func Mount(r chi.Router, d *ui.Deps) {
	h := &H{d}
	r.Get("/ui/hub", h.index)
	r.Get("/ui/hub/model", h.model)
}

// Model is a catalog card.
type Model struct {
	routing.GroupInfo
	Replicas  int
	Aliases   []string
	Requests7 int64
	Search    string // lowercase haystack for client-side filtering
}

// Status summarizes replica health for the card badge.
func (m Model) Status() string {
	switch {
	case m.Replicas == 0:
		return "unknown"
	case m.Healthy == 0:
		return "unhealthy"
	case m.Healthy < m.Replicas:
		return "cooldown"
	}
	return "healthy"
}

func (m Model) ModeLabel() string {
	switch m.Mode {
	case "", "chat":
		return "chat"
	}
	return m.Mode
}

type indexData struct {
	Models  []Model
	Modes   []string
	BaseURL string
	Total   int
	Scoped  bool
}

func (h *H) models(r *http.Request, p *auth.Principal, withUsage bool) []Model {
	allowed := p.AllowedModels(h.d.Registry)
	aliases := map[string][]string{}
	for a, t := range h.d.Registry.Aliases() {
		target := h.d.Registry.Resolve(t)
		aliases[target] = append(aliases[target], a)
	}
	usage := map[string]int64{}
	if withUsage {
		f := analytics.LastDays(7)
		if !p.CanViewAll() {
			teams := make([]string, 0, len(p.Memberships))
			for _, m := range p.Memberships {
				teams = append(teams, m.TeamID)
			}
			f.RestrictToUser(r.Context(), h.d.Store.Pool, p.UserID(), teams)
		}
		rows, _ := analytics.Breakdown(r.Context(), h.d.Store.Pool, f, "model", 500)
		for _, row := range rows {
			usage[row.Key] = row.Requests
		}
	}
	var out []Model
	for _, g := range h.d.Registry.Groups() {
		if allowed != nil && !slices.Contains(allowed, g.Name) {
			continue
		}
		enabled := 0
		for _, d := range g.Deployments {
			if d.Enabled {
				enabled++
			}
		}
		m := Model{GroupInfo: g, Replicas: enabled, Aliases: aliases[g.Name], Requests7: usage[g.Name]}
		sort.Strings(m.Aliases)
		m.Search = strings.ToLower(strings.Join(append([]string{g.Name, g.Description, g.Mode}, append(g.Tags, m.Aliases...)...), " "))
		out = append(out, m)
	}
	return out
}

func (h *H) index(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	ms := h.models(r, p, true)
	data := indexData{Models: ms, BaseURL: h.d.Cfg.BaseURL, Total: len(h.d.Registry.AllModelNames()), Scoped: !p.CanViewAll()}
	for _, m := range ms {
		if !slices.Contains(data.Modes, m.ModeLabel()) {
			data.Modes = append(data.Modes, m.ModeLabel())
		}
	}
	sort.Strings(data.Modes)
	h.d.Render(w, r, "hub/index", "hub", "Model hub", data)
}

type modelData struct {
	M       Model
	BaseURL string
	IsAdmin bool
	Example string // example input for snippets
}

func (h *H) model(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	name := r.URL.Query().Get("name")
	for _, m := range h.models(r, p, false) {
		if m.Name == name {
			h.d.Partial(w, r, 200, area, "hub-model", modelData{M: m, BaseURL: h.d.Cfg.BaseURL, IsAdmin: p.CanViewAll()})
			return
		}
	}
	ui.Fail(w, 404, "Model not found or not available to you")
}
