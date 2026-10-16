// Package tags manages request tags: spend attribution labels attached to keys or
// sent per request, with optional budgets and per-tag usage charts.
package tags

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"lemongate/internal/analytics"
	"lemongate/internal/store"
	"lemongate/internal/ui"
)

const area = "tags"

// Palette offered in the color picker (any hex color is accepted).
var Palette = []string{"#eab308", "#84cc16", "#22c55e", "#14b8a6", "#06b6d4", "#3b82f6", "#6366f1", "#a855f7", "#ec4899", "#f43f5e", "#f97316", "#64748b"}

var (
	nameRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,63}$`)
	colorRe = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
)

type H struct{ d *ui.Deps }

func Mount(r chi.Router, d *ui.Deps) {
	h := &H{d}
	r.Group(func(r chi.Router) {
		r.Use(ui.AdminWrites)
		r.Get("/ui/tags", h.index)
		r.Get("/ui/tags/table", h.table)
		r.Get("/ui/tags/new", h.newForm)
		r.Post("/ui/tags", h.create)
		r.Get("/ui/tags/{name}", h.show)
		r.Get("/ui/tags/{name}/edit", h.editForm)
		r.Post("/ui/tags/{name}", h.update)
		r.Post("/ui/tags/{name}/reset-spend", h.resetSpend)
		r.Post("/ui/tags/{name}/delete", h.delete)
	})
}

func days(r *http.Request) int {
	d, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if d <= 0 || d > 365 {
		d = 30
	}
	return d
}

// --- listing ---

type indexData struct {
	Days        int
	Total       store.TagUsage
	Registered  int
	Chart       analytics.ChartSpec
	Share       analytics.ChartSpec
	HasUsage    bool
	Suggestions []string
}

func (h *H) index(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	n := days(r)
	f := analytics.LastDays(n)
	id := indexData{Days: n}
	usage, _ := h.d.Store.TagUsageSummary(ctx, f.From, f.To)
	for _, u := range usage {
		id.Total.Requests += u.Requests
		id.Total.Cost += u.Cost
		id.Total.PromptTokens += u.PromptTokens
		id.Total.CompletionTokens += u.CompletionTokens
	}
	id.HasUsage = len(usage) > 0
	tags, _ := h.d.Store.ListTags(ctx)
	id.Registered = len(tags)
	id.Suggestions, _ = h.d.Store.UnregisteredTags(ctx)

	// Stacked daily spend for the top tags, the rest folded into "other".
	top := map[string]int{}
	var order []string
	for i, u := range usage {
		if i >= 6 {
			break
		}
		top[u.Tag] = i
		order = append(order, u.Tag)
	}
	daily, _ := h.d.Store.TagDaily(ctx, "", f.From, f.To)
	var labels []string
	idx := map[string]int{}
	for d, i := truncDay(f.From), 0; !d.After(truncDay(f.To)); d, i = d.AddDate(0, 0, 1), i+1 {
		labels = append(labels, d.Format("Jan 2"))
		idx[d.Format("2006-01-02")] = i
	}
	series := make([][]float64, len(order)+1)
	for i := range series {
		series[i] = make([]float64, len(labels))
	}
	for _, p := range daily {
		di, ok := idx[p.Day.Format("2006-01-02")]
		if !ok {
			continue
		}
		si, ok := top[p.Tag]
		if !ok {
			si = len(order)
		}
		series[si][di] += p.Cost
	}
	id.Chart = analytics.ChartSpec{Type: "bar", Format: "money", Stacked: true, Labels: labels}
	for i, name := range order {
		id.Chart.Datasets = append(id.Chart.Datasets, analytics.Dataset{Label: name, Data: series[i]})
	}
	if len(usage) > len(order) {
		id.Chart.Datasets = append(id.Chart.Datasets, analytics.Dataset{Label: "other", Data: series[len(order)]})
	}
	id.Share = analytics.ChartSpec{Type: "doughnut", Format: "money"}
	share := analytics.Dataset{Label: "Spend"}
	var other float64
	for i, u := range usage {
		if i < 6 {
			id.Share.Labels = append(id.Share.Labels, u.Tag)
			share.Data = append(share.Data, u.Cost)
		} else {
			other += u.Cost
		}
	}
	if other > 0 {
		id.Share.Labels = append(id.Share.Labels, "other")
		share.Data = append(share.Data, other)
	}
	id.Share.Datasets = []analytics.Dataset{share}
	h.d.Render(w, r, "tags/index", "tags", "Tags", id)
}

func truncDay(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

type tagRow struct {
	store.Tag
	Usage store.TagUsage
	Keys  int
}

type tableData struct {
	Rows     []tagRow
	Days     int
	MaxCost  float64
	Searched bool
}

func (h *H) table(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	n := days(r)
	f := analytics.LastDays(n)
	tags, err := h.d.Store.ListTags(ctx)
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	usage, _ := h.d.Store.TagUsageSummary(ctx, f.From, f.To)
	byTag := map[string]store.TagUsage{}
	for _, u := range usage {
		byTag[u.Tag] = u
	}
	counts, _ := h.d.Store.TagKeyCounts(ctx)
	q := r.URL.Query().Get("q")
	td := tableData{Days: n, Searched: q != ""}
	for _, t := range tags {
		if q != "" && !containsFold(t.Name, q) && !containsFold(t.Description, q) {
			continue
		}
		row := tagRow{Tag: t, Usage: byTag[t.Name], Keys: counts[t.Name]}
		if row.Usage.Cost > td.MaxCost {
			td.MaxCost = row.Usage.Cost
		}
		td.Rows = append(td.Rows, row)
	}
	h.d.Partial(w, r, 200, area, "tags-table", td)
}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

// --- forms ---

type formData struct {
	Tag     store.Tag
	IsNew   bool
	Error   string
	Palette []string
}

func (h *H) newForm(w http.ResponseWriter, r *http.Request) {
	t := store.Tag{Name: r.URL.Query().Get("name"), Color: Palette[0]}
	h.d.Partial(w, r, 200, area, "tag-form", formData{Tag: t, IsNew: true, Palette: Palette})
}

func bind(r *http.Request, t *store.Tag) error {
	_ = r.ParseForm()
	t.Description = ui.FormStr(r, "description")
	t.Color = ui.FormStr(r, "color")
	t.MaxBudget = ui.FormFloatPtr(r, "max_budget")
	t.BudgetPeriod = ui.FormStr(r, "budget_period")
	if t.Color != "" && !colorRe.MatchString(t.Color) {
		return errors.New("color must be a hex value like #84cc16")
	}
	if t.MaxBudget != nil && *t.MaxBudget < 0 {
		return errors.New("budget cannot be negative")
	}
	return nil
}

func (h *H) create(w http.ResponseWriter, r *http.Request) {
	var t store.Tag
	err := bind(r, &t)
	t.Name = ui.FormStr(r, "name")
	if err == nil && !nameRe.MatchString(t.Name) {
		err = errors.New("tag names are 1–64 characters: letters, digits and _ . : / - (starting with a letter or digit)")
	}
	if err == nil {
		if err = h.d.Store.CreateTag(r.Context(), t); errors.Is(err, store.ErrConflict) {
			err = errors.New("a tag with that name already exists")
		}
	}
	if err != nil {
		h.d.Partial(w, r, 422, area, "tag-form", formData{Tag: t, IsNew: true, Error: err.Error(), Palette: Palette})
		return
	}
	h.d.Changed()
	h.d.Audit(r, "create", "tag", t.Name, "Created tag "+t.Name, nil, t)
	ui.Done(w, "Tag created", "refresh-tags")
}

func (h *H) load(w http.ResponseWriter, r *http.Request) (store.Tag, bool) {
	name, _ := url.PathUnescape(chi.URLParam(r, "name"))
	t, err := h.d.Store.GetTag(r.Context(), name)
	if err != nil {
		if ui.IsHTMX(r) {
			ui.Fail(w, 404, "Tag not found")
		} else {
			http.NotFound(w, r)
		}
		return t, false
	}
	return t, true
}

func (h *H) editForm(w http.ResponseWriter, r *http.Request) {
	t, ok := h.load(w, r)
	if !ok {
		return
	}
	h.d.Partial(w, r, 200, area, "tag-form", formData{Tag: t, Palette: Palette})
}

func (h *H) update(w http.ResponseWriter, r *http.Request) {
	t, ok := h.load(w, r)
	if !ok {
		return
	}
	before := t
	err := bind(r, &t)
	if err == nil {
		err = h.d.Store.UpdateTag(r.Context(), t)
	}
	if err != nil {
		h.d.Partial(w, r, 422, area, "tag-form", formData{Tag: t, Error: err.Error(), Palette: Palette})
		return
	}
	h.d.Changed()
	h.d.Audit(r, "update", "tag", t.Name, "Updated tag "+t.Name, before, t)
	ui.Done(w, "Tag updated", "refresh-tags", "refresh-tag")
}

func (h *H) resetSpend(w http.ResponseWriter, r *http.Request) {
	t, ok := h.load(w, r)
	if !ok {
		return
	}
	_ = h.d.Store.ResetTagSpend(r.Context(), t.Name)
	h.d.Changed()
	h.d.Audit(r, "reset_spend", "tag", t.Name, "Reset spend for tag "+t.Name, map[string]any{"spend": t.Spend}, nil)
	ui.Done(w, "Spend reset", "refresh-tags", "refresh-tag")
}

func (h *H) delete(w http.ResponseWriter, r *http.Request) {
	t, ok := h.load(w, r)
	if !ok {
		return
	}
	if err := h.d.Store.DeleteTag(r.Context(), t.Name); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Changed()
	h.d.Audit(r, "delete", "tag", t.Name, "Deleted tag "+t.Name, t, nil)
	if r.URL.Query().Get("from") == "detail" {
		ui.Toast(w, "success", "Tag deleted")
		ui.Redirect(w, r, "/ui/tags")
		return
	}
	ui.Done(w, "Tag deleted", "refresh-tags")
}

// --- detail ---

type showData struct {
	Tag     store.Tag
	Days    int
	Totals  store.TagUsage
	Chart   analytics.ChartSpec
	ByModel []store.TagUsage
	Keys    []store.Key
}

func (h *H) show(w http.ResponseWriter, r *http.Request) {
	t, ok := h.load(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	n := days(r)
	f := analytics.LastDays(n)
	sd := showData{Tag: t, Days: n}
	sd.ByModel, _ = h.d.Store.TagModelUsage(ctx, t.Name, f.From, f.To)
	for _, m := range sd.ByModel {
		sd.Totals.Requests += m.Requests
		sd.Totals.Failures += m.Failures
		sd.Totals.Cost += m.Cost
		sd.Totals.PromptTokens += m.PromptTokens
		sd.Totals.CompletionTokens += m.CompletionTokens
	}
	daily, _ := h.d.Store.TagDaily(ctx, t.Name, f.From, f.To)
	byDay := map[string]store.TagDay{}
	for _, p := range daily {
		byDay[p.Day.Format("2006-01-02")] = p
	}
	cost := analytics.Dataset{Label: "Spend"}
	sd.Chart = analytics.ChartSpec{Type: "bar", Format: "money"}
	for d := truncDay(f.From); !d.After(truncDay(f.To)); d = d.AddDate(0, 0, 1) {
		sd.Chart.Labels = append(sd.Chart.Labels, d.Format("Jan 2"))
		cost.Data = append(cost.Data, byDay[d.Format("2006-01-02")].Cost)
	}
	sd.Chart.Datasets = []analytics.Dataset{cost}
	sd.Keys, _ = h.d.Store.KeysWithTag(ctx, t.Name)
	if r.Header.Get("HX-Target") == "tag-detail" {
		h.d.Partial(w, r, 200, area, "tag-detail", sd)
		return
	}
	h.d.Render(w, r, "tags/show", "tags", t.Name, sd, ui.Crumb{Label: "Tags", Href: "/ui/tags"})
}
