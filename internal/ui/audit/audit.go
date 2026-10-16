// Package audit shows the admin audit log with before/after diffs.
package audit

import (
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"

	"github.com/go-chi/chi/v5"

	"lemongate/internal/store"
	"lemongate/internal/ui"
)

const area = "audit"

const pageSize = 50

type H struct{ d *ui.Deps }

// Mount registers routes for this area on the session-protected router.
func Mount(r chi.Router, d *ui.Deps) {
	h := &H{d}
	r.Group(func(r chi.Router) {
		r.Use(ui.RequireViewer)
		r.Get("/ui/audit", h.index)
		r.Get("/ui/audit/table", h.table)
	})
}

type indexData struct {
	Types   []string
	Actions []string
	Type    string
	Query   string
}

func (h *H) index(w http.ResponseWriter, r *http.Request) {
	types, _ := h.d.Store.AuditEntityTypes(r.Context())
	actions, _ := h.d.Store.AuditActions(r.Context())
	q := r.URL.Query()
	h.d.Render(w, r, "audit/index", "audit", "Audit log", indexData{Types: types, Actions: actions, Type: q.Get("type"), Query: q.Get("q")})
}

// DiffRow is one field of a before/after comparison.
type DiffRow struct {
	Field   string
	Before  string
	After   string
	Changed bool
	Added   bool
	Removed bool
}

type Entry struct {
	store.AuditEntry
	Diff    []DiffRow
	Changes int
	Link    string
}

type tableData struct {
	Entries []Entry
	Total   int
	Page    int
	Pages   int
	From    int
	To      int
	Query   string // encoded filter params without page
}

func (h *H) table(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	list, total, err := h.d.Store.ListAuditFiltered(r.Context(), q.Get("type"), q.Get("action"), q.Get("q"), pageSize, (page-1)*pageSize)
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	td := tableData{Total: total, Page: page, Pages: (total + pageSize - 1) / pageSize}
	if td.Pages == 0 {
		td.Pages = 1
	}
	if total > 0 {
		td.From = (page-1)*pageSize + 1
		td.To = td.From + len(list) - 1
	}
	params := url.Values{}
	for _, k := range []string{"type", "action", "q"} {
		if v := q.Get(k); v != "" {
			params.Set(k, v)
		}
	}
	td.Query = params.Encode()
	for _, e := range list {
		en := Entry{AuditEntry: e, Diff: diff(e.Before, e.After), Link: link(e.EntityType, e.EntityID)}
		for _, d := range en.Diff {
			if d.Changed {
				en.Changes++
			}
		}
		td.Entries = append(td.Entries, en)
	}
	h.d.Partial(w, r, 200, area, "audit-table", td)
}

func link(typ, id string) string {
	if id == "" {
		return ""
	}
	switch typ {
	case "key":
		return "/ui/keys/" + id
	case "team":
		return "/ui/teams/" + id
	case "user":
		return "/ui/users/" + id
	case "org", "organization":
		return "/ui/orgs/" + id
	case "deployment", "model":
		return "/ui/models"
	case "credential":
		return "/ui/credentials"
	case "settings":
		return "/ui/settings"
	case "tag":
		return "/ui/tags"
	case "end_user":
		return "/ui/end-users"
	}
	return ""
}

func render(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case string:
		return x
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// diff compares the top-level fields of before and after.
func diff(before, after map[string]any) []DiffRow {
	if before == nil && after == nil {
		return nil
	}
	keys := map[string]bool{}
	for k := range before {
		keys[k] = true
	}
	for k := range after {
		keys[k] = true
	}
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	var out []DiffRow
	for _, k := range names {
		b, inB := before[k]
		a, inA := after[k]
		row := DiffRow{Field: k}
		switch {
		case before == nil:
			row.After, row.Added, row.Changed = render(a), true, true
		case after == nil:
			row.Before, row.Removed, row.Changed = render(b), true, true
		default:
			row.Before, row.After = render(b), render(a)
			row.Changed = !reflect.DeepEqual(b, a) || inA != inB
		}
		out = append(out, row)
	}
	// Changed fields first, keep alphabetical order within each group.
	sort.SliceStable(out, func(i, j int) bool { return out[i].Changed && !out[j].Changed })
	return out
}
