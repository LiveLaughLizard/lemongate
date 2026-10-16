// Package budgets manages reusable budget presets and shows a budget health overview
// across every spend-bearing entity (keys, users, teams, orgs, tags, end users).
package budgets

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"lemongate/internal/store"
	"lemongate/internal/ui"
)

const area = "budgets"

type H struct{ d *ui.Deps }

func Mount(r chi.Router, d *ui.Deps) {
	h := &H{d}
	r.Group(func(r chi.Router) {
		r.Use(ui.AdminWrites)
		r.Get("/ui/budgets", h.index)
		r.Get("/ui/budgets/health", h.health)
		r.Get("/ui/budgets/presets", h.presets)
		r.Get("/ui/budgets/presets/new", h.newForm)
		r.Post("/ui/budgets/presets", h.create)
		r.Get("/ui/budgets/presets/{id}/edit", h.editForm)
		r.Post("/ui/budgets/presets/{id}", h.update)
		r.Post("/ui/budgets/presets/{id}/delete", h.delete)
		r.Get("/ui/budgets/presets/{id}/apply", h.applyForm)
		r.Post("/ui/budgets/presets/{id}/apply", h.apply)
		r.Get("/ui/budgets/targets", h.targets)
	})
}

// kinds in display order.
var kinds = []kindInfo{
	{"key", "API keys", "key-round"},
	{"user", "Users", "user-round"},
	{"team", "Teams", "users"},
	{"org", "Organizations", "building-2"},
	{"tag", "Tags", "tag"},
	{"end_user", "End users", "contact"},
}

type kindInfo struct{ Key, Label, Icon string }

type bucketView struct {
	kindInfo
	store.BudgetBucket
}

type indexData struct {
	Buckets  []bucketView
	Budgeted int
	Warn     int
	Over     int
	Presets  int
}

func (h *H) index(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	bs, _ := h.d.Store.BudgetBuckets(ctx)
	by := map[string]store.BudgetBucket{}
	for _, b := range bs {
		by[b.Kind] = b
	}
	id := indexData{}
	for _, k := range kinds {
		b := by[k.Key]
		id.Buckets = append(id.Buckets, bucketView{k, b})
		id.Budgeted += b.Total
		id.Warn += b.Warn
		id.Over += b.Over
	}
	ps, _ := h.d.Store.ListBudgetPresets(ctx)
	id.Presets = len(ps)
	h.d.Render(w, r, "budgets/index", "budgets", "Budgets", id)
}

type healthData struct {
	Rows      []store.BudgetEntity
	Threshold int
	Kind      string
	Labels    map[string]kindInfo
}

func (h *H) health(w http.ResponseWriter, r *http.Request) {
	th, err := strconv.Atoi(r.URL.Query().Get("threshold"))
	if err != nil || th < 0 || th > 1000 {
		th = 70
	}
	kind := r.URL.Query().Get("kind")
	rows, err := h.d.Store.BudgetHealth(r.Context(), float64(th), kind, 200)
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	labels := map[string]kindInfo{}
	for _, k := range kinds {
		labels[k.Key] = k
	}
	h.d.Partial(w, r, 200, area, "budget-health", healthData{Rows: rows, Threshold: th, Kind: kind, Labels: labels})
}

// --- presets ---

func (h *H) presets(w http.ResponseWriter, r *http.Request) {
	ps, err := h.d.Store.ListBudgetPresets(r.Context())
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Partial(w, r, 200, area, "preset-list", ps)
}

type formData struct {
	Preset store.BudgetPreset
	IsNew  bool
	Error  string
}

func (h *H) newForm(w http.ResponseWriter, r *http.Request) {
	h.d.Partial(w, r, 200, area, "preset-form", formData{IsNew: true, Preset: store.BudgetPreset{BudgetPeriod: "monthly"}})
}

func bind(r *http.Request, b *store.BudgetPreset) error {
	_ = r.ParseForm()
	b.Name = ui.FormStr(r, "name")
	b.MaxBudget = ui.FormFloatPtr(r, "max_budget")
	b.BudgetPeriod = ui.FormStr(r, "budget_period")
	b.RPMLimit, b.TPMLimit, b.MaxParallel = ui.FormIntPtr(r, "rpm_limit"), ui.FormIntPtr(r, "tpm_limit"), ui.FormIntPtr(r, "max_parallel")
	switch {
	case b.Name == "":
		return errors.New("give the preset a name")
	case len(b.Name) > 80:
		return errors.New("name is too long (max 80 characters)")
	case b.MaxBudget != nil && *b.MaxBudget < 0:
		return errors.New("budget cannot be negative")
	case b.MaxBudget == nil && b.RPMLimit == nil && b.TPMLimit == nil && b.MaxParallel == nil:
		return errors.New("set at least a budget or one limit")
	}
	return nil
}

func (h *H) save(w http.ResponseWriter, r *http.Request, b store.BudgetPreset, before *store.BudgetPreset) {
	isNew := before == nil
	err := bind(r, &b)
	if err == nil {
		if err = h.d.Store.SaveBudgetPreset(r.Context(), b); errors.Is(err, store.ErrConflict) {
			err = errors.New("a preset with that name already exists")
		}
	}
	if err != nil {
		h.d.Partial(w, r, 422, area, "preset-form", formData{Preset: b, IsNew: isNew, Error: err.Error()})
		return
	}
	if isNew {
		h.d.Audit(r, "create", "budget_preset", b.Name, "Created budget preset "+b.Name, nil, b)
		ui.Done(w, "Preset created", "refresh-presets")
		return
	}
	h.d.Audit(r, "update", "budget_preset", b.ID, "Updated budget preset "+b.Name, before, b)
	ui.Done(w, "Preset updated", "refresh-presets")
}

func (h *H) create(w http.ResponseWriter, r *http.Request) { h.save(w, r, store.BudgetPreset{}, nil) }

func (h *H) load(w http.ResponseWriter, r *http.Request) (store.BudgetPreset, bool) {
	b, err := h.d.Store.GetBudgetPreset(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		ui.Fail(w, 404, "Preset not found")
		return b, false
	}
	return b, true
}

func (h *H) editForm(w http.ResponseWriter, r *http.Request) {
	b, ok := h.load(w, r)
	if !ok {
		return
	}
	h.d.Partial(w, r, 200, area, "preset-form", formData{Preset: b})
}

func (h *H) update(w http.ResponseWriter, r *http.Request) {
	b, ok := h.load(w, r)
	if !ok {
		return
	}
	before := b
	h.save(w, r, b, &before)
}

func (h *H) delete(w http.ResponseWriter, r *http.Request) {
	b, ok := h.load(w, r)
	if !ok {
		return
	}
	if err := h.d.Store.DeleteBudgetPreset(r.Context(), b.ID); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Audit(r, "delete", "budget_preset", b.ID, "Deleted budget preset "+b.Name, b, nil)
	ui.Done(w, "Preset deleted", "refresh-presets")
}

// --- apply ---

type applyData struct {
	Preset  store.BudgetPreset
	Kind    string
	Targets []store.PresetTarget
	Target  string
	Error   string
}

var applyKinds = map[string]string{"key": "key", "user": "user", "team": "team", "org": "org"}

func (h *H) applyForm(w http.ResponseWriter, r *http.Request) {
	b, ok := h.load(w, r)
	if !ok {
		return
	}
	ad := applyData{Preset: b, Kind: "key"}
	ad.Targets, _ = h.d.Store.PresetTargets(r.Context(), ad.Kind)
	h.d.Partial(w, r, 200, area, "preset-apply", ad)
}

func (h *H) targets(w http.ResponseWriter, r *http.Request) {
	kind := applyKinds[r.URL.Query().Get("kind")]
	if kind == "" {
		kind = "key"
	}
	ts, _ := h.d.Store.PresetTargets(r.Context(), kind)
	h.d.Partial(w, r, 200, area, "preset-targets", applyData{Kind: kind, Targets: ts})
}

func (h *H) apply(w http.ResponseWriter, r *http.Request) {
	b, ok := h.load(w, r)
	if !ok {
		return
	}
	_ = r.ParseForm()
	kind, target := applyKinds[ui.FormStr(r, "kind")], ui.FormStr(r, "target")
	fail := func(msg string) {
		ad := applyData{Preset: b, Kind: kind, Target: target, Error: msg}
		if ad.Kind == "" {
			ad.Kind = "key"
		}
		ad.Targets, _ = h.d.Store.PresetTargets(r.Context(), ad.Kind)
		h.d.Partial(w, r, 422, area, "preset-apply", ad)
	}
	if kind == "" || target == "" {
		fail("Choose what to apply the preset to.")
		return
	}
	label := target
	ts, _ := h.d.Store.PresetTargets(r.Context(), kind)
	for _, t := range ts {
		if t.ID == target {
			label = t.Name
		}
	}
	if err := h.d.Store.ApplyBudgetPreset(r.Context(), kind, target, b); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			fail("That target no longer exists.")
		} else {
			fail(err.Error())
		}
		return
	}
	h.d.Changed()
	h.d.Audit(r, "apply_preset", kind, target, "Applied budget preset "+b.Name+" to "+kind+" "+label, nil, b)
	ui.Done(w, "Applied "+b.Name+" to "+label, "refresh-budgets")
}
