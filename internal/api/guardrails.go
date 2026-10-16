package api

import (
	"errors"
	"net/http"
	"strings"

	"lemongate/internal/guardrails"
	"lemongate/internal/ui/guardrailsui"
)

func (h *H) guardrailRoutes() []route {
	return []route{
		{Method: "GET", Path: "/guardrail-policies", Tag: "Extensions", Summary: "List guardrail policies",
			Desc:   "Policies are named bundles of guardrails. `key_count` and `team_count` are the active keys and teams that attach each policy.",
			Access: accessViewer, Resp: "list:GuardrailPolicy", handler: h.listPolicies},
		{Method: "POST", Path: "/guardrail-policies", Tag: "Extensions", Summary: "Create guardrail policy",
			Desc:   "Every name in `guardrails` must be an existing guardrail. Attach the policy to keys and teams through their `policies` field, make it `default_on`, or request it per call with the body field `\"guardrails\": [\"<policy>\"]`.",
			Access: accessViewer, Body: "GuardrailPolicyInput", Resp: "GuardrailPolicy", Status: 201,
			Example: `{"name": "support-bot", "description": "Public support assistant", "guardrails": ["customer-facing-strict-pii", "prompt-injection-heuristics-block"], "default_on": false}`,
			handler: h.createPolicy},
		{Method: "GET", Path: "/guardrail-policies/{id}", Tag: "Extensions", Summary: "Get guardrail policy", Desc: "`{id}` accepts the id or the unique name.",
			Access: accessViewer, Resp: "GuardrailPolicy", handler: h.getPolicy},
		{Method: "PATCH", Path: "/guardrail-policies/{id}", Tag: "Extensions", Summary: "Update guardrail policy",
			Desc:   "Partial update: only the fields present are changed. Renaming updates references on keys and teams.",
			Access: accessViewer, Body: "GuardrailPolicyInput", Resp: "GuardrailPolicy", Example: `{"default_on": true}`, handler: h.updatePolicy},
		{Method: "DELETE", Path: "/guardrail-policies/{id}", Tag: "Extensions", Summary: "Delete guardrail policy",
			Desc:   "Removes the policy and its references on keys and teams. With `with_guardrails=true`, guardrails used by no other policy are deleted too.",
			Access: accessViewer, Query: []qparam{{"with_guardrails", "boolean", "Also delete guardrails used only by this policy"}}, Resp: "Deleted", handler: h.deletePolicy},

		{Method: "GET", Path: "/guardrail-presets", Tag: "Extensions", Summary: "List guardrail presets",
			Desc:   "The built-in preset catalog with install status. `packs` describes the preset groups.",
			Access: accessViewer, Resp: "list:GuardrailPreset", handler: h.listGuardrailPresets},
		{Method: "POST", Path: "/guardrail-presets/{id}/install", Tag: "Extensions", Summary: "Install or update preset",
			Desc: "Creates the preset's guardrails and a policy named after the preset (or updates them when already installed). " +
				"`params` supplies the preset's inputs, e.g. `model` (a configured model name) or a comma-separated list. " +
				"`mode` and `action` optionally override every guardrail. Returns 409 when a guardrail name is taken by a guardrail the preset did not create.",
			Access: accessViewer, Body: "PresetInstallInput", Resp: "GuardrailPolicy",
			Example: `{"params": {"model": "llama-guard-3-8b"}, "default_on": true}`, handler: h.installPreset},
		{Method: "DELETE", Path: "/guardrail-presets/{id}", Tag: "Extensions", Summary: "Uninstall preset",
			Desc:   "Deletes the preset's policy and the guardrails used by no other policy.",
			Access: accessViewer, Resp: "Deleted", handler: h.uninstallPreset},
		{Method: "GET", Path: "/guardrail-catalog", Tag: "Extensions", Summary: "Guardrail catalog",
			Desc:   "Everything needed to build a guardrail `config`: kinds, guard model families with their hazard categories, PII entities, content categories and code languages.",
			Access: accessViewer, Resp: "GuardrailCatalog", handler: h.guardrailCatalog},
	}
}

// policyOut is a policy with its key and team reference counts.
type policyOut struct {
	guardrails.Policy
	KeyCount  int `json:"key_count"`
	TeamCount int `json:"team_count"`
}

type policyInput struct {
	Name        *string   `json:"name"`
	Description *string   `json:"description"`
	Guardrails  *[]string `json:"guardrails"`
	DefaultOn   *bool     `json:"default_on"`
	Enabled     *bool     `json:"enabled"`
}

func (in policyInput) apply(p *guardrails.Policy) {
	if in.Name != nil {
		p.Name = *in.Name
	}
	if in.Description != nil {
		p.Description = strings.TrimSpace(*in.Description)
	}
	if in.Guardrails != nil {
		p.Guardrails = *in.Guardrails
	}
	if in.DefaultOn != nil {
		p.DefaultOn = *in.DefaultOn
	}
	if in.Enabled != nil {
		p.Enabled = *in.Enabled
	}
}

type presetParamOut struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Help     string `json:"help"`
	Type     string `json:"type"`
	Family   string `json:"family,omitempty"`
	Mode     string `json:"mode,omitempty"`
	Required bool   `json:"required"`
	Default  string `json:"default,omitempty"`
}

type presetGuardrailOut struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Mode        string `json:"mode"`
	Action      string `json:"action"`
	Description string `json:"description"`
}

type presetOut struct {
	ID            string               `json:"id"`
	Pack          string               `json:"pack"`
	Title         string               `json:"title"`
	Description   string               `json:"description"`
	Icon          string               `json:"icon"`
	Latency       string               `json:"latency"`
	RequiresModel bool                 `json:"requires_model"`
	Params        []presetParamOut     `json:"params"`
	Guardrails    []presetGuardrailOut `json:"guardrails"`
	Installed     bool                 `json:"installed"`
	Policy        *guardrails.Policy   `json:"policy"`
}

type packOut struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

type presetInstallInput struct {
	Params    map[string]string `json:"params"`
	DefaultOn bool              `json:"default_on"`
	Mode      string            `json:"mode"`
	Action    string            `json:"action"`
}

type entityOut struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Group   string `json:"group"`
	Mask    string `json:"mask"`
	Hint    string `json:"hint"`
	Context bool   `json:"context"`
}

type labeled struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
}

type catalogOut struct {
	Kinds        []guardrailsui.KindInfo `json:"kinds"`
	Families     []guardrails.FamilyMeta `json:"families"`
	EntityGroups []string                `json:"entity_groups"`
	Entities     []entityOut             `json:"entities"`
	Categories   []labeled               `json:"categories"`
	Languages    []labeled               `json:"languages"`
	Modes        []string                `json:"modes"`
	Actions      []string                `json:"actions"`
}

func (h *H) engine(w http.ResponseWriter) (*guardrails.Engine, bool) {
	if hk := hooks.Load(); hk != nil && hk.Guardrails != nil {
		return hk.Guardrails, true
	}
	fail(w, http.StatusServiceUnavailable, "unavailable", "guardrails are not enabled")
	return nil, false
}

func policyErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, guardrails.ErrNotFound):
		notFound(w, "guardrail policy")
	case errors.Is(err, guardrails.ErrConflict):
		fail(w, http.StatusConflict, "conflict", "a policy with this name already exists")
	case isDBError(err):
		storeErr(w, err, "guardrail policy")
	default:
		badRequest(w, "%s", err.Error())
	}
}

func (h *H) policyOut(r *http.Request, p guardrails.Policy) policyOut {
	refs := guardrailsui.PolicyUsage(r.Context(), h.d)[p.Name]
	return policyOut{Policy: p, KeyCount: refs.Keys, TeamCount: refs.Teams}
}

func (h *H) listPolicies(w http.ResponseWriter, r *http.Request) {
	eng, ok := h.engine(w)
	if !ok {
		return
	}
	pols, err := eng.ListPolicies(r.Context())
	if err != nil {
		storeErr(w, err, "guardrail policy")
		return
	}
	usage := guardrailsui.PolicyUsage(r.Context(), h.d)
	out := make([]policyOut, 0, len(pols))
	for _, p := range pols {
		out = append(out, policyOut{Policy: p, KeyCount: usage[p.Name].Keys, TeamCount: usage[p.Name].Teams})
	}
	writeJSON(w, 200, list(out))
}

func (h *H) getPolicy(w http.ResponseWriter, r *http.Request) {
	eng, ok := h.engine(w)
	if !ok {
		return
	}
	p, err := eng.GetPolicy(r.Context(), param(r, "id"))
	if err != nil {
		policyErr(w, err)
		return
	}
	writeJSON(w, 200, h.policyOut(r, p))
}

func (h *H) createPolicy(w http.ResponseWriter, r *http.Request) {
	eng, ok := h.engine(w)
	if !ok {
		return
	}
	var in policyInput
	if !decode(w, r, &in) {
		return
	}
	p := guardrails.Policy{Enabled: true}
	in.apply(&p)
	if err := eng.SavePolicy(r.Context(), &p); err != nil {
		policyErr(w, err)
		return
	}
	h.d.Changed()
	h.d.Audit(r, "create", "guardrail_policy", p.ID, "Created guardrail policy "+p.Name+" via API", nil, p)
	p, _ = eng.GetPolicy(r.Context(), p.ID)
	writeJSON(w, http.StatusCreated, h.policyOut(r, p))
}

func (h *H) updatePolicy(w http.ResponseWriter, r *http.Request) {
	eng, ok := h.engine(w)
	if !ok {
		return
	}
	p, err := eng.GetPolicy(r.Context(), param(r, "id"))
	if err != nil {
		policyErr(w, err)
		return
	}
	before := p
	var in policyInput
	if !decode(w, r, &in) {
		return
	}
	in.apply(&p)
	if err := eng.SavePolicy(r.Context(), &p); err != nil {
		policyErr(w, err)
		return
	}
	h.d.Changed()
	h.d.Audit(r, "update", "guardrail_policy", p.ID, "Updated guardrail policy "+p.Name+" via API", before, p)
	p, _ = eng.GetPolicy(r.Context(), p.ID)
	writeJSON(w, 200, h.policyOut(r, p))
}

func (h *H) deletePolicy(w http.ResponseWriter, r *http.Request) {
	eng, ok := h.engine(w)
	if !ok {
		return
	}
	p, err := eng.GetPolicy(r.Context(), param(r, "id"))
	if err != nil {
		policyErr(w, err)
		return
	}
	withG := r.URL.Query().Get("with_guardrails") == "true" || r.URL.Query().Get("with_guardrails") == "1"
	if err := eng.DeletePolicy(r.Context(), p.ID, withG); err != nil {
		policyErr(w, err)
		return
	}
	h.d.Changed()
	summary := "Deleted guardrail policy " + p.Name + " via API"
	if withG {
		summary = "Deleted guardrail policy " + p.Name + " and its guardrails via API"
	}
	h.d.Audit(r, "delete", "guardrail_policy", p.ID, summary, p, nil)
	writeJSON(w, 200, deleted(p.ID))
}

func toPresetOut(p guardrails.Preset, installed map[string]guardrails.Policy) presetOut {
	o := presetOut{ID: p.ID, Pack: p.Pack, Title: p.Title, Description: p.Description, Icon: p.Icon, Latency: p.Latency,
		RequiresModel: p.RequiresModel(), Params: []presetParamOut{}, Guardrails: []presetGuardrailOut{}}
	for _, pr := range p.Params {
		o.Params = append(o.Params, presetParamOut{ID: pr.ID, Label: pr.Label, Help: pr.Help, Type: pr.Type, Family: pr.Family,
			Mode: pr.Mode, Required: pr.Required, Default: pr.Default})
	}
	names := p.GuardrailNames()
	for i, g := range p.Guardrails {
		o.Guardrails = append(o.Guardrails, presetGuardrailOut{Name: names[i], Kind: g.Kind, Mode: g.Mode, Action: g.Action, Description: g.Description})
	}
	if pol, ok := installed[p.ID]; ok {
		o.Installed, o.Policy = true, &pol
	}
	return o
}

func (h *H) listGuardrailPresets(w http.ResponseWriter, r *http.Request) {
	eng, ok := h.engine(w)
	if !ok {
		return
	}
	installed, err := eng.InstalledPresets(r.Context())
	if err != nil {
		storeErr(w, err, "guardrail preset")
		return
	}
	out := make([]presetOut, 0, len(guardrails.Presets))
	for _, p := range guardrails.Presets {
		out = append(out, toPresetOut(p, installed))
	}
	packs := make([]packOut, 0, len(guardrails.Packs))
	for _, p := range guardrails.Packs {
		packs = append(packs, packOut{ID: p.ID, Label: p.Label, Description: p.Description})
	}
	resp := list(out)
	resp["packs"] = packs
	writeJSON(w, 200, resp)
}

func (h *H) installPreset(w http.ResponseWriter, r *http.Request) {
	eng, ok := h.engine(w)
	if !ok {
		return
	}
	p, found := guardrails.PresetByID(param(r, "id"))
	if !found {
		notFound(w, "guardrail preset")
		return
	}
	var in presetInstallInput
	if !decode(w, r, &in) {
		return
	}
	installed, err := eng.InstalledPresets(r.Context())
	if err != nil {
		storeErr(w, err, "guardrail preset")
		return
	}
	before, was := installed[p.ID]
	pol, err := eng.InstallPreset(r.Context(), p.ID, guardrails.InstallOptions{Params: in.Params, DefaultOn: in.DefaultOn, Mode: in.Mode, Action: in.Action})
	if err != nil {
		switch {
		case errors.Is(err, guardrails.ErrPresetConflict), strings.Contains(err.Error(), "already exists"):
			fail(w, http.StatusConflict, "conflict", err.Error())
		case isDBError(err):
			storeErr(w, err, "guardrail preset")
		default:
			badRequest(w, "%s", err.Error())
		}
		return
	}
	h.d.Changed()
	if fresh, err := eng.GetPolicy(r.Context(), pol.ID); err == nil {
		pol = fresh
	}
	if was {
		h.d.Audit(r, "update", "guardrail_policy", pol.ID, "Updated preset "+p.Title+" via API", before, pol)
	} else {
		h.d.Audit(r, "create", "guardrail_policy", pol.ID, "Installed preset "+p.Title+" as policy "+pol.Name+" via API", nil, pol)
	}
	writeJSON(w, 200, h.policyOut(r, pol))
}

func (h *H) uninstallPreset(w http.ResponseWriter, r *http.Request) {
	eng, ok := h.engine(w)
	if !ok {
		return
	}
	p, found := guardrails.PresetByID(param(r, "id"))
	if !found {
		notFound(w, "guardrail preset")
		return
	}
	installed, err := eng.InstalledPresets(r.Context())
	if err != nil {
		storeErr(w, err, "guardrail preset")
		return
	}
	pol, ok := installed[p.ID]
	if !ok {
		fail(w, http.StatusNotFound, "not_found", "preset "+p.ID+" is not installed")
		return
	}
	if err := eng.DeletePolicy(r.Context(), pol.ID, true); err != nil {
		policyErr(w, err)
		return
	}
	h.d.Changed()
	h.d.Audit(r, "delete", "guardrail_policy", pol.ID, "Uninstalled preset "+p.Title+" via API", pol, nil)
	writeJSON(w, 200, deleted(pol.ID))
}

func (h *H) guardrailCatalog(w http.ResponseWriter, _ *http.Request) {
	c := catalogOut{Kinds: guardrailsui.Kinds, Families: guardrails.AllFamilies(), EntityGroups: guardrails.EntityGroups(),
		Modes: guardrails.Modes, Actions: guardrails.Actions}
	for _, e := range guardrails.Entities {
		c.Entities = append(c.Entities, entityOut{ID: e.ID, Label: e.Label, Group: e.Group, Mask: e.Mask, Hint: e.Hint, Context: e.Context})
	}
	for _, cat := range guardrails.ContentCategories {
		c.Categories = append(c.Categories, labeled{ID: cat.ID, Label: cat.Label, Description: cat.Description})
	}
	for _, l := range guardrails.CodeLanguages {
		c.Languages = append(c.Languages, labeled{ID: l.ID, Label: l.Label})
	}
	writeJSON(w, 200, c)
}
