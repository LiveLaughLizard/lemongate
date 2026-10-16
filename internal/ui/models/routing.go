package models

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"

	"lemongate/internal/auth"
	"lemongate/internal/store"
	"lemongate/internal/ui"
)

// --- aliases ---

type aliasRow struct {
	Alias      string
	Target     string
	FromConfig bool
	Overrides  bool // DB alias shadowing a config alias
	Missing    bool // target is not a known model group
}

type aliasesData struct {
	Rows    []aliasRow
	CanEdit bool
}

func (h *H) aliases(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	db, _ := h.d.Store.ListAliases(r.Context())
	inDB := map[string]bool{}
	var rows []aliasRow
	for _, a := range db {
		inDB[a.Alias] = true
		_, cfg := h.d.Cfg.File.Aliases[a.Alias]
		rows = append(rows, aliasRow{Alias: a.Alias, Target: a.Target, Overrides: cfg})
	}
	for a, t := range h.d.Cfg.File.Aliases {
		if !inDB[a] {
			rows = append(rows, aliasRow{Alias: a, Target: t, FromConfig: true})
		}
	}
	for i := range rows {
		rows[i].Missing = !h.d.Registry.HasGroup(h.d.Registry.Resolve(rows[i].Target))
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Alias < rows[j].Alias })
	h.d.Partial(w, r, 200, area, "aliases-table", aliasesData{Rows: rows, CanEdit: p.IsAdmin()})
}

type aliasForm struct {
	Alias  string
	Target string
	Orig   string
	Models []string
	Error  string
}

func (h *H) aliasForm(w http.ResponseWriter, r *http.Request) {
	af := aliasForm{Models: h.d.Registry.AllModelNames(), Target: r.URL.Query().Get("target")}
	if a := r.URL.Query().Get("alias"); a != "" {
		af.Alias, af.Orig = a, a
		af.Target = h.d.Registry.Aliases()[a]
	}
	h.d.Partial(w, r, 200, area, "alias-form", af)
}

func (h *H) saveAlias(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	af := aliasForm{Alias: ui.FormStr(r, "alias"), Target: ui.FormStr(r, "target"), Orig: ui.FormStr(r, "orig"), Models: h.d.Registry.AllModelNames()}
	fail := func(msg string) {
		af.Error = msg
		h.d.Partial(w, r, 422, area, "alias-form", af)
	}
	switch {
	case !modelNameRe.MatchString(af.Alias):
		fail("alias is required (letters, digits and . _ : / @ + -; no spaces)")
		return
	case af.Target == "":
		fail("choose the model group this alias points to")
		return
	case af.Alias == af.Target:
		fail("an alias cannot point to itself")
		return
	case h.d.Registry.HasGroup(af.Alias):
		fail("a model group with that name exists; aliases cannot shadow real models")
		return
	case af.Orig != af.Alias:
		if _, exists := h.d.Registry.Aliases()[af.Alias]; exists {
			if _, cfg := h.d.Cfg.File.Aliases[af.Alias]; !cfg {
				fail("that alias already exists")
				return
			}
		}
	}
	before := map[string]any(nil)
	if af.Orig != "" {
		before = map[string]any{"alias": af.Orig, "target": h.d.Registry.Aliases()[af.Orig]}
		if af.Orig != af.Alias {
			_ = h.d.Store.DeleteAlias(r.Context(), af.Orig)
		}
	}
	if err := h.d.Store.UpsertAlias(r.Context(), af.Alias, af.Target); err != nil {
		fail(err.Error())
		return
	}
	h.d.ReloadModels(r.Context())
	action := "create"
	if af.Orig != "" {
		action = "update"
	}
	h.d.Audit(r, action, "alias", af.Alias, fmt.Sprintf("Alias %s → %s", af.Alias, af.Target), before, map[string]any{"alias": af.Alias, "target": af.Target})
	ui.Done(w, "Alias saved", "refresh-aliases", "refresh-models")
}

func (h *H) deleteAlias(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	a := ui.FormStr(r, "alias")
	target := h.d.Registry.Aliases()[a]
	if err := h.d.Store.DeleteAlias(r.Context(), a); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			ui.Fail(w, 409, "This alias is defined in the config file and cannot be deleted here.")
			return
		}
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.ReloadModels(r.Context())
	h.d.Audit(r, "delete", "alias", a, "Deleted alias "+a, map[string]any{"alias": a, "target": target}, nil)
	ui.Done(w, "Alias deleted", "refresh-aliases", "refresh-models")
}

// --- access groups ---

type groupRow struct {
	Name        string
	Description string
	Models      []string
	FromConfig  bool
	Missing     []string
	KeyCount    int
}

type groupsData struct {
	Rows    []groupRow
	CanEdit bool
}

func (h *H) groups(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	db, _ := h.d.Store.ListAccessGroups(r.Context())
	inDB := map[string]bool{}
	var rows []groupRow
	for _, g := range db {
		inDB[g.Name] = true
		rows = append(rows, groupRow{Name: g.Name, Description: g.Description, Models: g.Models})
	}
	for n, m := range h.d.Cfg.File.AccessGroups {
		if !inDB[n] {
			rows = append(rows, groupRow{Name: n, Models: m, FromConfig: true})
		}
	}
	counts := map[string]int{}
	if rs, err := h.d.Store.Pool.Query(r.Context(), `SELECT g, count(*) FROM api_keys, unnest(access_groups) g WHERE deleted_at IS NULL GROUP BY g`); err == nil {
		for rs.Next() {
			var g string
			var n int
			if rs.Scan(&g, &n) == nil {
				counts[g] = n
			}
		}
		rs.Close()
	}
	for i := range rows {
		rows[i].KeyCount = counts[rows[i].Name]
		for _, m := range rows[i].Models {
			if !h.d.Registry.HasGroup(m) {
				rows[i].Missing = append(rows[i].Missing, m)
			}
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	h.d.Partial(w, r, 200, area, "groups-table", groupsData{Rows: rows, CanEdit: p.IsAdmin()})
}

type groupForm struct {
	Group  store.AccessGroup
	Orig   string
	Models []string
	Error  string
}

func (h *H) groupForm(w http.ResponseWriter, r *http.Request) {
	gf := groupForm{Models: h.d.Registry.AllModelNames()}
	if n := r.URL.Query().Get("name"); n != "" {
		gf.Orig = n
		gf.Group = store.AccessGroup{Name: n, Models: h.d.Cfg.File.AccessGroups[n]}
		if gs, err := h.d.Store.ListAccessGroups(r.Context()); err == nil {
			for _, g := range gs {
				if g.Name == n {
					gf.Group = g
				}
			}
		}
	}
	h.d.Partial(w, r, 200, area, "group-form", gf)
}

func (h *H) saveGroup(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	gf := groupForm{Orig: ui.FormStr(r, "orig"), Models: h.d.Registry.AllModelNames(),
		Group: store.AccessGroup{Name: ui.FormStr(r, "name"), Description: ui.FormStr(r, "description"), Models: ui.FormList(r, "models")}}
	fail := func(msg string) {
		gf.Error = msg
		h.d.Partial(w, r, 422, area, "group-form", gf)
	}
	if !modelNameRe.MatchString(gf.Group.Name) {
		fail("name is required (letters, digits and . _ : / @ + -; no spaces)")
		return
	}
	if len(gf.Group.Models) == 0 {
		fail("select at least one model")
		return
	}
	if gf.Orig != gf.Group.Name && slices.Contains(h.d.Registry.AccessGroupNames(), gf.Group.Name) {
		if _, cfg := h.d.Cfg.File.AccessGroups[gf.Group.Name]; !cfg {
			fail("an access group with that name already exists")
			return
		}
	}
	var before any
	if gf.Orig != "" {
		before = map[string]any{"name": gf.Orig, "models": h.d.Registry.ExpandAccessGroups([]string{gf.Orig})}
		if gf.Orig != gf.Group.Name {
			_ = h.d.Store.DeleteAccessGroup(r.Context(), gf.Orig)
		}
	}
	if err := h.d.Store.UpsertAccessGroup(r.Context(), gf.Group); err != nil {
		fail(err.Error())
		return
	}
	h.d.ReloadModels(r.Context())
	h.d.Changed()
	action := "create"
	if gf.Orig != "" {
		action = "update"
	}
	h.d.Audit(r, action, "access_group", gf.Group.Name, "Saved access group "+gf.Group.Name, before, gf.Group)
	ui.Done(w, "Access group saved", "refresh-groups")
}

func (h *H) deleteGroup(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	n := ui.FormStr(r, "name")
	if err := h.d.Store.DeleteAccessGroup(r.Context(), n); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			ui.Fail(w, 409, "This access group is defined in the config file and cannot be deleted here.")
			return
		}
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.ReloadModels(r.Context())
	h.d.Changed()
	h.d.Audit(r, "delete", "access_group", n, "Deleted access group "+n, map[string]any{"name": n}, nil)
	ui.Done(w, "Access group deleted", "refresh-groups")
}

// --- fallbacks ---

type fallbackRow struct {
	Model      string
	Kind       string
	Targets    []string
	FromConfig bool
	Missing    []string
}

type fallbacksData struct {
	Rows    []fallbackRow
	CanEdit bool
}

func (h *H) fallbacks(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	db, _ := h.d.Store.ListFallbacks(r.Context())
	inDB := map[string]bool{}
	var rows []fallbackRow
	for _, f := range db {
		inDB[f.Kind+"|"+f.Model] = true
		rows = append(rows, fallbackRow{Model: f.Model, Kind: f.Kind, Targets: f.Targets})
	}
	for m, t := range h.d.Cfg.File.Fallbacks {
		if !inDB["general|"+m] {
			rows = append(rows, fallbackRow{Model: m, Kind: "general", Targets: t, FromConfig: true})
		}
	}
	for m, t := range h.d.Cfg.File.ContextFallbacks {
		if !inDB["context|"+m] {
			rows = append(rows, fallbackRow{Model: m, Kind: "context", Targets: t, FromConfig: true})
		}
	}
	for i := range rows {
		for _, t := range rows[i].Targets {
			if !h.d.Registry.HasGroup(h.d.Registry.Resolve(t)) {
				rows[i].Missing = append(rows[i].Missing, t)
			}
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Model != rows[j].Model {
			return rows[i].Model < rows[j].Model
		}
		return rows[i].Kind < rows[j].Kind
	})
	h.d.Partial(w, r, 200, area, "fallbacks-table", fallbacksData{Rows: rows, CanEdit: p.IsAdmin()})
}

type fallbackForm struct {
	FB     store.Fallback
	IsNew  bool
	Models []string
	Error  string
}

func (h *H) fallbackForm(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ff := fallbackForm{Models: h.d.Registry.AllModelNames(), IsNew: q.Get("model") == "" || q.Get("new") == "1",
		FB: store.Fallback{Model: q.Get("model"), Kind: q.Get("kind")}}
	if ff.FB.Kind == "" {
		ff.FB.Kind = "general"
	}
	if !ff.IsNew {
		ff.FB.Targets = h.d.Registry.Fallbacks(ff.FB.Model, ff.FB.Kind == "context")
	}
	if ff.FB.Targets == nil {
		ff.FB.Targets = []string{}
	}
	h.d.Partial(w, r, 200, area, "fallback-form", ff)
}

func (h *H) saveFallback(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	ff := fallbackForm{Models: h.d.Registry.AllModelNames(), IsNew: ui.FormBool(r, "is_new"),
		FB: store.Fallback{Model: ui.FormStr(r, "model"), Kind: ui.FormStr(r, "kind"), Targets: ui.FormList(r, "targets")}}
	fail := func(msg string) {
		if ff.FB.Targets == nil {
			ff.FB.Targets = []string{}
		}
		ff.Error = msg
		h.d.Partial(w, r, 422, area, "fallback-form", ff)
	}
	switch {
	case ff.FB.Model == "":
		fail("choose the model these fallbacks apply to")
		return
	case ff.FB.Kind != "general" && ff.FB.Kind != "context":
		fail("choose when the fallback applies")
		return
	case len(ff.FB.Targets) == 0:
		fail("add at least one fallback target")
		return
	case slices.Contains(ff.FB.Targets, ff.FB.Model):
		fail("a model cannot fall back to itself")
		return
	}
	before := h.d.Registry.Fallbacks(ff.FB.Model, ff.FB.Kind == "context")
	if err := h.d.Store.UpsertFallback(r.Context(), ff.FB); err != nil {
		fail(err.Error())
		return
	}
	h.d.ReloadModels(r.Context())
	var b any
	if len(before) > 0 {
		b = map[string]any{"model": ff.FB.Model, "kind": ff.FB.Kind, "targets": before}
	}
	h.d.Audit(r, "update", "fallback", ff.FB.Kind+":"+ff.FB.Model, fmt.Sprintf("Set %s fallbacks for %s", ff.FB.Kind, ff.FB.Model), b, ff.FB)
	ui.Done(w, "Fallbacks saved", "refresh-fallbacks", "refresh-model")
}

func (h *H) deleteFallback(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	m, k := ui.FormStr(r, "model"), ui.FormStr(r, "kind")
	before := h.d.Registry.Fallbacks(m, k == "context")
	if err := h.d.Store.DeleteFallback(r.Context(), m, k); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			ui.Fail(w, 409, "These fallbacks are defined in the config file and cannot be deleted here.")
			return
		}
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.ReloadModels(r.Context())
	h.d.Audit(r, "delete", "fallback", k+":"+m, fmt.Sprintf("Removed %s fallbacks for %s", k, m), map[string]any{"model": m, "kind": k, "targets": before}, nil)
	ui.Done(w, "Fallbacks removed", "refresh-fallbacks", "refresh-model")
}
