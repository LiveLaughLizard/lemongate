package guardrailsui

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"

	"lemongate/internal/auth"
	"lemongate/internal/guardrails"
	"lemongate/internal/ui"
)

// Preset and pack icons are chosen at runtime from the catalog; listing them here
// lets the asset build find and embed them.
var _ = []string{icon("fingerprint"), icon("shield-alert"), icon("bug-off"), icon("scale"), icon("key-round"), icon("flag"),
	icon("euro"), icon("landmark"), icon("message-square-warning"), icon("eye-off"), icon("shield-check"), icon("radar"),
	icon("waypoints"), icon("terminal"), icon("wrench"), icon("heart-pulse"), icon("credit-card"), icon("swords"), icon("headset")}

// NeedsLabel describes the model a preset requires ("" when it needs none).
func NeedsLabel(p guardrails.Preset) string {
	for _, pr := range p.Params {
		if pr.Type == "model" {
			if pr.Family != "" {
				return pr.Label
			}
			return strings.ToLower(pr.Label)
		}
	}
	return ""
}

type presetCard struct {
	guardrails.Preset
	PackLabel string
	Needs     string
	Count     int
	Installed bool
	Policy    guardrails.Policy
}

type presetGridData struct {
	Cards   []presetCard
	CanEdit bool
}

func packLabel(id string) string {
	for _, p := range guardrails.Packs {
		if p.ID == id {
			return p.Label
		}
	}
	return id
}

func (h *H) presetGrid(w http.ResponseWriter, r *http.Request) {
	installed, err := h.eng.InstalledPresets(r.Context())
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	gd := presetGridData{CanEdit: auth.FromContext(r.Context()).IsAdmin()}
	for _, p := range guardrails.Presets {
		pol, ok := installed[p.ID]
		gd.Cards = append(gd.Cards, presetCard{Preset: p, PackLabel: packLabel(p.Pack), Needs: NeedsLabel(p), Count: len(p.Guardrails), Installed: ok, Policy: pol})
	}
	h.d.Partial(w, r, 200, area, "presets-grid", gd)
}

// --- install modal ---

type paramField struct {
	guardrails.PresetParam
	Value       string
	Suggested   []modelOpt // models whose mode matches the param's mode
	Other       []modelOpt
	FamilyLabel string
}

type previewRow struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	KindLabel   string `json:"kind_label"`
	Icon        string `json:"icon"`
	Mode        string `json:"mode"`
	Action      string `json:"action"`
	CanMask     bool   `json:"can_mask"`
	Description string `json:"description"`
	Conflict    bool   `json:"conflict"`
}

type installData struct {
	P           guardrails.Preset
	PackLabel   string
	Error       string
	Installed   bool
	Policy      guardrails.Policy
	Params      []paramField
	Preview     []previewRow
	DefaultOn   bool
	Mode        string
	Action      string
	ModeOptions []string
	AnyMask     bool
	Conflicts   []string
	CanEdit     bool
}

// allowedModes is the set of mode overrides every guardrail of the preset accepts.
func allowedModes(p guardrails.Preset) []string {
	out := []string{guardrails.ModePre, guardrails.ModePost, guardrails.ModeBoth}
	for _, g := range p.Guardrails {
		if g.Kind != guardrails.KindGuardModel {
			continue
		}
		fm, ok := guardrails.FamilyInfo(g.Config.Family)
		if !ok {
			continue
		}
		out = slices.DeleteFunc(out, func(m string) bool {
			if m == guardrails.ModeBoth {
				return len(fm.Phases) < 2
			}
			return !slices.Contains(fm.Phases, m)
		})
	}
	return out
}

func (h *H) installData(ctx context.Context, p guardrails.Preset, values map[string]string, defaultOn bool, mode, action, errMsg string) installData {
	installed, _ := h.eng.InstalledPresets(ctx)
	pol, isInstalled := installed[p.ID]
	existing, _ := h.eng.List(ctx)
	byName := map[string]guardrails.Guardrail{}
	for _, g := range existing {
		byName[g.Name] = g
	}
	d := installData{P: p, PackLabel: packLabel(p.Pack), Error: errMsg, Installed: isInstalled, Policy: pol,
		DefaultOn: defaultOn, Mode: mode, Action: action, ModeOptions: allowedModes(p), CanEdit: auth.FromContext(ctx).IsAdmin()}
	models := h.modelOptions()
	for _, pr := range p.Params {
		f := paramField{PresetParam: pr, Value: values[pr.ID]}
		if pr.Type == "model" {
			for _, m := range models {
				if m.Mode == pr.Mode {
					f.Suggested = append(f.Suggested, m)
				} else {
					f.Other = append(f.Other, m)
				}
			}
			if fm, ok := guardrails.FamilyInfo(pr.Family); ok {
				f.FamilyLabel = fm.Label
				// Models whose name looks like the family go first, and the first is preselected.
				slices.SortStableFunc(f.Suggested, func(a, b modelOpt) int {
					return boolRank(looksLike(b.Name, pr.Family)) - boolRank(looksLike(a.Name, pr.Family))
				})
				if f.Value == "" && len(f.Suggested) > 0 && looksLike(f.Suggested[0].Name, pr.Family) {
					f.Value = f.Suggested[0].Name
				}
			}
			// Keep a configured model that has since been removed so updating shows it.
			if f.Value != "" && !slices.ContainsFunc(models, func(m modelOpt) bool { return m.Name == f.Value }) {
				f.Other = append(f.Other, modelOpt{Name: f.Value, Mode: "missing"})
			}
		}
		d.Params = append(d.Params, f)
	}
	for i, g := range p.Guardrails {
		name := p.GuardrailNames()[i]
		k := Kind(g.Kind)
		old, exists := byName[name]
		conflict := exists && old.Preset != p.ID
		if conflict {
			d.Conflicts = append(d.Conflicts, name)
		}
		if k.CanMask {
			d.AnyMask = true
		}
		d.Preview = append(d.Preview, previewRow{Name: name, Kind: g.Kind, KindLabel: k.Label, Icon: k.Icon, Mode: g.Mode, Action: g.Action,
			CanMask: k.CanMask, Description: g.Description, Conflict: conflict})
	}
	return d
}

// currentValues reconstructs install inputs from an installed preset's guardrails.
func (h *H) currentValues(ctx context.Context, p guardrails.Preset) (values map[string]string, mode, action string) {
	values = map[string]string{}
	for _, pr := range p.Params {
		values[pr.ID] = pr.Default
	}
	list, err := h.eng.List(ctx)
	if err != nil {
		return values, "", ""
	}
	byName := map[string]guardrails.Guardrail{}
	for _, g := range list {
		byName[g.Name] = g
	}
	names := p.GuardrailNames()
	modes, actions := map[string]bool{}, map[string]bool{}
	sameAsDefault := true
	for i, pg := range p.Guardrails {
		g, ok := byName[names[i]]
		if !ok || g.Preset != p.ID {
			continue
		}
		modes[g.Mode], actions[g.Action] = true, true
		if g.Mode != pg.Mode || g.Action != pg.Action {
			sameAsDefault = false
		}
		if pg.ModelParam != "" && g.Config.Model != "" {
			values[pg.ModelParam] = g.Config.Model
		}
		if pg.WordsParam != "" {
			var extra []string
			for _, w := range g.Config.Words {
				if !slices.Contains(pg.Config.Words, w) {
					extra = append(extra, w)
				}
			}
			values[pg.WordsParam] = strings.Join(extra, ", ")
		}
	}
	if !sameAsDefault {
		if len(modes) == 1 {
			for m := range modes {
				mode = m
			}
		}
		if len(actions) == 1 {
			for a := range actions {
				action = a
			}
		}
	}
	return values, mode, action
}

func (h *H) preset(w http.ResponseWriter, r *http.Request) (guardrails.Preset, bool) {
	p, ok := guardrails.PresetByID(chi.URLParam(r, "id"))
	if !ok {
		ui.Fail(w, 404, "Unknown preset")
	}
	return p, ok
}

func (h *H) installForm(w http.ResponseWriter, r *http.Request) {
	p, ok := h.preset(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	installed, _ := h.eng.InstalledPresets(ctx)
	values, mode, action := h.currentValues(ctx, p)
	pol, isInstalled := installed[p.ID]
	h.d.Partial(w, r, 200, area, "preset-install", h.installData(ctx, p, values, isInstalled && pol.DefaultOn, mode, action, ""))
}

func (h *H) install(w http.ResponseWriter, r *http.Request) {
	p, ok := h.preset(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	_ = r.ParseForm()
	opts := guardrails.InstallOptions{Params: map[string]string{}, DefaultOn: ui.FormBool(r, "default_on"),
		Mode: ui.FormStr(r, "mode"), Action: ui.FormStr(r, "action")}
	for _, pr := range p.Params {
		opts.Params[pr.ID] = ui.FormStr(r, "param_"+pr.ID)
	}
	installed, _ := h.eng.InstalledPresets(ctx)
	before, wasInstalled := installed[p.ID]
	pol, err := h.eng.InstallPreset(ctx, p.ID, opts)
	if err != nil {
		msg := err.Error()
		if errors.Is(err, guardrails.ErrPresetConflict) {
			msg = "Cannot install: " + msg + ". Rename or delete that guardrail first, then try again."
		}
		h.d.Partial(w, r, 422, area, "preset-install", h.installData(ctx, p, opts.Params, opts.DefaultOn, opts.Mode, opts.Action, msg))
		return
	}
	h.d.Changed()
	if wasInstalled {
		h.d.Audit(r, "update", "guardrail_policy", pol.ID, "Updated preset "+p.Title, before, pol)
		ui.Done(w, "Updated "+p.Title, refreshAll...)
		return
	}
	h.d.Audit(r, "create", "guardrail_policy", pol.ID, "Installed preset "+p.Title+" as policy "+pol.Name, nil, pol)
	ui.Done(w, "Installed "+p.Title+" as policy "+pol.Name, refreshAll...)
}

func (h *H) uninstall(w http.ResponseWriter, r *http.Request) {
	p, ok := h.preset(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	installed, err := h.eng.InstalledPresets(ctx)
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	pol, ok := installed[p.ID]
	if !ok {
		ui.Fail(w, 404, p.Title+" is not installed")
		return
	}
	if err := h.eng.DeletePolicy(ctx, pol.ID, true); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Changed()
	h.d.Audit(r, "delete", "guardrail_policy", pol.ID, "Uninstalled preset "+p.Title, pol, nil)
	ui.Done(w, "Uninstalled "+p.Title, refreshAll...)
}

// looksLike reports whether a model name suggests it serves the guard model family
// (e.g. "llama-guard-3-8b" for llama_guard).
func looksLike(name, family string) bool {
	norm := func(s string) string {
		return strings.NewReplacer("-", "", "_", "", " ", "", ".", "").Replace(strings.ToLower(s))
	}
	return family != "" && strings.Contains(norm(name), norm(family))
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}
