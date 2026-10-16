// Package guardrailsui is the console area for guardrails: the preset gallery,
// policies, guardrail definitions, a test bench and the intervention log.
package guardrailsui

import (
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"lemongate/internal/auth"
	"lemongate/internal/guardrails"
	"lemongate/internal/ui"
)

const area = "guardrails"

// refreshAll is fired after any change that affects presets, policies and guardrails.
var refreshAll = []string{"refresh-guardrails", "refresh-policies", "refresh-presets"}

type H struct {
	d   *ui.Deps
	eng *guardrails.Engine
}

// Mount registers routes for this area on the session-protected router.
func Mount(r chi.Router, d *ui.Deps, eng *guardrails.Engine) {
	h := &H{d: d, eng: eng}
	r.Group(func(r chi.Router) {
		r.Use(ui.AdminWrites)
		r.Get("/ui/guardrails", h.index)
		r.Get("/ui/guardrails/table", h.table)
		r.Get("/ui/guardrails/events", h.events)
		r.Get("/ui/guardrails/new", h.newForm)
		r.Post("/ui/guardrails", h.create)
		r.Get("/ui/guardrails/{id}/edit", h.editForm)
		r.Post("/ui/guardrails/{id}", h.update)
		r.Post("/ui/guardrails/{id}/toggle", h.toggle)
		r.Post("/ui/guardrails/{id}/delete", h.delete)

		r.Get("/ui/guardrails/presets/grid", h.presetGrid)
		r.Get("/ui/guardrails/presets/{id}/install", h.installForm)
		r.Post("/ui/guardrails/presets/{id}/install", h.install)
		r.Post("/ui/guardrails/presets/{id}/uninstall", h.uninstall)

		r.Get("/ui/guardrails/policies/table", h.policyTable)
		r.Get("/ui/guardrails/policies/new", h.newPolicy)
		r.Post("/ui/guardrails/policies", h.createPolicy)
		r.Get("/ui/guardrails/policies/{id}/edit", h.editPolicy)
		r.Post("/ui/guardrails/policies/{id}", h.updatePolicy)
		r.Post("/ui/guardrails/policies/{id}/toggle", h.togglePolicy)
		r.Get("/ui/guardrails/policies/{id}/delete", h.confirmDeletePolicy)
		r.Post("/ui/guardrails/policies/{id}/delete", h.deletePolicy)
	})
	// The test bench has no side effects, so read-only admins may use it too.
	r.With(ui.RequireViewer).Post("/ui/guardrails/test", h.test)
}

// KindInfo describes a guardrail kind for the console.
type KindInfo struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Icon        string `json:"icon"`
	Blurb       string `json:"description"`
	CanMask     bool   `json:"can_mask"`
	ModelBacked bool   `json:"model_backed"`
}

// Kinds lists guardrail kinds in display order.
var Kinds = []KindInfo{
	{ID: guardrails.KindPII, Label: "PII & secrets", Icon: icon("fingerprint"), Blurb: "Detect and mask personal data and secrets with a regional entity library (US, EU, UK, Canada, Australia, financial, health) and checksum validation."},
	{ID: guardrails.KindBlocklist, Label: "Content & keywords", Icon: icon("ban"), Blurb: "Built-in content categories (profanity, sexual, hate, violence, …) plus your own words and phrases, matched on word boundaries."},
	{ID: guardrails.KindPromptInjection, Label: "Prompt injection", Icon: icon("bug-off"), Blurb: "Heuristic scoring of instruction overrides, jailbreak personas, system-prompt extraction and encoded payloads. No model needed."},
	{ID: guardrails.KindCodeExecution, Label: "Dangerous code", Icon: icon("terminal"), Blurb: "Detect destructive or remote-execution code: shell one-liners, reverse shells, destructive SQL, encoded PowerShell."},
	{ID: guardrails.KindToolPolicy, Label: "Tool policy", Icon: icon("wrench"), Blurb: "Allow or deny tool definitions and tool calls by name, with glob patterns such as *delete*."},
	{ID: guardrails.KindGuardModel, Label: "Guard model", Icon: icon("radar"), Blurb: "Purpose-built safety models served by vLLM: Llama Guard, Granite Guardian, Qwen3Guard, ShieldGemma and Prompt Guard.", ModelBacked: true},
	{ID: guardrails.KindSemantic, Label: "Semantic similarity", Icon: icon("waypoints"), Blurb: "Flag text that is semantically close to known attack examples, using one of your embedding models.", ModelBacked: true},
	{ID: guardrails.KindLLMJudge, Label: "LLM judge", Icon: icon("scale"), Blurb: "Ask one of your chat models whether the text satisfies a written policy.", ModelBacked: true},
	{ID: guardrails.KindRegex, Label: "Custom regex", Icon: icon("regex"), Blurb: "Your own patterns, each with an optional replacement."},
	{ID: guardrails.KindMaxLength, Label: "Max input length", Icon: icon("ruler"), Blurb: "Reject requests whose text exceeds a character budget."},
}

func init() {
	for i := range Kinds {
		Kinds[i].CanMask = guardrails.CanMask(Kinds[i].ID)
	}
}

func icon(s string) string { return s }

// Kind returns display info for a kind id.
func Kind(id string) KindInfo {
	for _, k := range Kinds {
		if k.ID == id {
			return k
		}
	}
	return KindInfo{ID: id, Label: id, Icon: "shield-check"}
}

func kindMap() map[string]KindInfo {
	m := make(map[string]KindInfo, len(Kinds))
	for _, k := range Kinds {
		m[k.ID] = k
	}
	return m
}

// --- index ---

var tabs = []string{"presets", "policies", "list", "bench", "events"}

type indexData struct {
	Tab         string
	CanEdit     bool
	Total       int
	Enabled     int
	DefaultOn   int
	Policies    int
	PolicyOn    int
	FromPresets int
	Events24h   int
	Blocked24h  int
	Masked24h   int
	Guardrails  []guardrails.Guardrail
	PolicyList  []guardrails.Policy
	Kinds       []KindInfo
	Packs       []guardrails.Pack
	Presets     int
	// Test bench preselection.
	BenchPolicy    string
	BenchGuardrail string
	KindsByID      map[string]KindInfo
}

func (h *H) index(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	ctx := r.Context()
	list, err := h.eng.List(ctx)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	pols, err := h.eng.ListPolicies(ctx)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	q := r.URL.Query()
	tab := q.Get("tab")
	if !slices.Contains(tabs, tab) {
		tab = "presets"
	}
	d := indexData{Tab: tab, CanEdit: p.IsAdmin(), Total: len(list), Guardrails: list, PolicyList: pols, Kinds: Kinds,
		Packs: guardrails.Packs, Presets: len(guardrails.Presets), Policies: len(pols),
		BenchPolicy: q.Get("policy"), BenchGuardrail: q.Get("guardrail"), KindsByID: kindMap()}
	for _, g := range list {
		if g.Enabled {
			d.Enabled++
			if g.DefaultOn {
				d.DefaultOn++
			}
		}
	}
	for _, pl := range pols {
		if pl.Enabled && pl.DefaultOn {
			d.PolicyOn++
		}
		if pl.Preset != "" {
			d.FromPresets++
		}
	}
	byAction, _ := h.eng.EventCounts(ctx, time.Now().Add(-24*time.Hour))
	for _, n := range byAction {
		d.Events24h += n
	}
	d.Blocked24h, d.Masked24h = byAction["block"], byAction["mask"]
	h.d.Render(w, r, "guardrails/index", "guardrails", "Guardrails", d)
}

// --- guardrails table ---

type row struct {
	guardrails.Guardrail
	Kind     KindInfo
	Refs     int
	Events   int
	Invalid  string
	Summary  string
	Policies []string
	InOnPol  bool // part of an enabled default-on policy
}

type tableData struct {
	Rows    []row
	CanEdit bool
}

func (h *H) table(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	list, err := h.eng.List(ctx)
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	pols, err := h.eng.ListPolicies(ctx)
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	inPolicies := map[string][]string{}
	viaDefault := map[string]bool{}
	for _, p := range pols {
		for _, g := range p.Guardrails {
			inPolicies[g] = append(inPolicies[g], p.Name)
			if p.Enabled && p.DefaultOn {
				viaDefault[g] = true
			}
		}
	}
	usage := h.eng.Usage(ctx)
	_, byG := h.eng.EventCounts(ctx, time.Now().Add(-24*time.Hour))
	td := tableData{CanEdit: auth.FromContext(ctx).IsAdmin()}
	for _, g := range list {
		td.Rows = append(td.Rows, row{Guardrail: g, Kind: Kind(g.Kind), Refs: usage[g.Name] - len(inPolicies[g.Name]), Events: byG[g.Name],
			Invalid: h.eng.CompileError(g.Name), Summary: summary(g), Policies: inPolicies[g.Name], InOnPol: viaDefault[g.Name]})
	}
	h.d.Partial(w, r, 200, area, "guardrails-table", td)
}

// summary is a one-line description of a guardrail's config.
func summary(g guardrails.Guardrail) string {
	c := g.Config
	switch g.Kind {
	case guardrails.KindPII:
		return clip(c.Entities, 6)
	case guardrails.KindBlocklist:
		var parts []string
		if len(c.Categories) > 0 {
			parts = append(parts, "categories: "+strings.Join(c.Categories, ", "))
		}
		if len(c.Words) > 0 {
			parts = append(parts, "words: "+clip(c.Words, 6))
		}
		return strings.Join(parts, " · ")
	case guardrails.KindRegex:
		ps := make([]string, 0, len(c.Patterns))
		for _, p := range c.Patterns {
			ps = append(ps, p.Pattern)
		}
		return strings.Join(ps, "  ·  ")
	case guardrails.KindMaxLength:
		return ui.Num(c.MaxChars) + " characters"
	case guardrails.KindPromptInjection:
		th := c.Threshold
		if th <= 0 {
			th = guardrails.DefaultInjectionThreshold
		}
		return "sensitivity threshold " + strconv.FormatFloat(th, 'f', 2, 64)
	case guardrails.KindCodeExecution:
		if len(c.Languages) == 0 {
			return "all languages"
		}
		return strings.Join(c.Languages, ", ")
	case guardrails.KindToolPolicy:
		var parts []string
		if len(c.AllowTools) > 0 {
			parts = append(parts, "allow "+clip(c.AllowTools, 4))
		}
		if len(c.DenyTools) > 0 {
			parts = append(parts, "deny "+clip(c.DenyTools, 4))
		}
		return strings.Join(parts, " · ")
	case guardrails.KindSemantic:
		return c.Model + " · " + strconv.Itoa(len(c.Examples)) + " examples · " + failMode(c)
	case guardrails.KindGuardModel:
		fam := c.Family
		if fm, ok := guardrails.FamilyInfo(c.Family); ok {
			fam = fm.Label
		}
		return fam + " · " + c.Model + " · " + failMode(c)
	case guardrails.KindLLMJudge:
		return c.Model + " · " + failMode(c)
	}
	return ""
}

func failMode(c guardrails.Config) string {
	if c.FailOpen {
		return "fail-open"
	}
	return "fail-closed"
}

func clip(xs []string, n int) string {
	if len(xs) > n {
		return strings.Join(xs[:n], ", ") + " +" + strconv.Itoa(len(xs)-n)
	}
	return strings.Join(xs, ", ")
}

// --- form ---

type entityGroup struct {
	Name     string
	Entities []guardrails.Entity
	Selected int
}

type modelOpt struct {
	Name string `json:"name"`
	Mode string `json:"mode"`
}

type formData struct {
	G            guardrails.Guardrail
	IsNew        bool
	Error        string
	Kinds        []KindInfo
	EntityGroups []entityGroup
	Categories   []guardrails.Category
	Languages    []guardrails.Language
	Families     []guardrails.FamilyMeta
	Family       string
	Hazards      []string
	Models       []modelOpt
	ChatModels   []string
	EmbedModels  []string
	OtherModels  []string // models for the semantic select that are not embedding models
	Words        string
	Examples     string
	Allow        string
	Deny         string
	Patterns     []guardrails.Pattern
	InjThreshold float64
	SemThreshold float64
	GMThreshold  float64
	Timeout      int
}

func groupEntities(selected []string) []entityGroup {
	var out []entityGroup
	for _, name := range guardrails.EntityGroups() {
		eg := entityGroup{Name: name}
		for _, e := range guardrails.Entities {
			if e.Group == name {
				eg.Entities = append(eg.Entities, e)
				if slices.Contains(selected, e.ID) {
					eg.Selected++
				}
			}
		}
		if len(eg.Entities) > 0 {
			out = append(out, eg)
		}
	}
	return out
}

// modelOptions lists configured model groups with their mode ("chat" when unset).
// A currently configured model that no longer exists is kept so editing does not lose it.
func (h *H) modelOptions(keep ...string) []modelOpt {
	var out []modelOpt
	seen := map[string]bool{}
	for _, g := range h.d.Registry.Groups() {
		mode := g.Mode
		if mode == "" {
			mode = "chat"
		}
		out = append(out, modelOpt{Name: g.Name, Mode: mode})
		seen[g.Name] = true
	}
	for _, k := range keep {
		if k != "" && !seen[k] {
			out = append(out, modelOpt{Name: k, Mode: "missing"})
			seen[k] = true
		}
	}
	return out
}

func (h *H) form(g guardrails.Guardrail, isNew bool, errMsg string) formData {
	c := g.Config
	pats := c.Patterns
	if len(pats) == 0 {
		pats = []guardrails.Pattern{{}}
	}
	fd := formData{G: g, IsNew: isNew, Error: errMsg, Kinds: Kinds, EntityGroups: groupEntities(c.Entities),
		Categories: guardrails.ContentCategories, Languages: guardrails.CodeLanguages, Families: guardrails.AllFamilies(),
		Models: h.modelOptions(c.Model), Words: strings.Join(c.Words, "\n"), Examples: strings.Join(c.Examples, "\n"),
		Allow: strings.Join(c.AllowTools, "\n"), Deny: strings.Join(c.DenyTools, "\n"), Patterns: pats,
		InjThreshold: guardrails.DefaultInjectionThreshold, SemThreshold: 0.85, Timeout: c.TimeoutSeconds}
	for _, m := range fd.Models {
		switch m.Mode {
		case "chat", "completion", "missing":
			fd.ChatModels = append(fd.ChatModels, m.Name)
		}
		if m.Mode == "embedding" {
			fd.EmbedModels = append(fd.EmbedModels, m.Name)
		} else {
			fd.OtherModels = append(fd.OtherModels, m.Name)
		}
	}
	if fd.Timeout <= 0 {
		fd.Timeout = 15
	}
	fd.Family = c.Family
	if fd.Family == "" {
		fd.Family = guardrails.FamilyLlamaGuard
	}
	fm, _ := guardrails.FamilyInfo(fd.Family)
	fd.Hazards = c.Hazards
	if len(fd.Hazards) == 0 || g.Kind != guardrails.KindGuardModel {
		fd.Hazards = fm.DefaultHazards
	}
	if fd.Hazards == nil {
		fd.Hazards = []string{}
	}
	fd.GMThreshold = fm.DefaultThreshold
	if c.Threshold > 0 {
		switch g.Kind {
		case guardrails.KindPromptInjection:
			fd.InjThreshold = c.Threshold
		case guardrails.KindSemantic:
			fd.SemThreshold = c.Threshold
		case guardrails.KindGuardModel:
			fd.GMThreshold = c.Threshold
		}
	}
	if fd.GMThreshold <= 0 {
		fd.GMThreshold = 0.5
	}
	return fd
}

func (h *H) newForm(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	if Kind(kind).Blurb == "" {
		kind = guardrails.KindPII
	}
	action := guardrails.ActionBlock
	if guardrails.CanMask(kind) {
		action = guardrails.ActionMask
	}
	g := guardrails.Guardrail{Kind: kind, Mode: guardrails.ModePre, Action: action, Enabled: true,
		Config: guardrails.Config{Entities: []string{guardrails.EntityEmail, guardrails.EntityPhone, guardrails.EntitySSN,
			guardrails.EntityCreditCard, guardrails.EntityIPv4, guardrails.EntitySecret}, TimeoutSeconds: 15}}
	h.d.Partial(w, r, 200, area, "guardrail-form", h.form(g, true, ""))
}

func formFloat(r *http.Request, k string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(r.FormValue(k)), 64)
	return f
}

func bind(r *http.Request, g *guardrails.Guardrail) {
	_ = r.ParseForm()
	g.Name = ui.FormStr(r, "name")
	g.Description = ui.FormStr(r, "description")
	g.Kind = ui.FormStr(r, "kind")
	g.Mode = ui.FormStr(r, "mode")
	g.Action = ui.FormStr(r, "action")
	g.DefaultOn = ui.FormBool(r, "default_on")
	g.Enabled = ui.FormBool(r, "enabled")
	c := guardrails.Config{}
	modelBacked := func(model string) {
		c.Model = model
		c.FailOpen = ui.FormStr(r, "fail_mode") == "open"
		c.TimeoutSeconds = ui.FormInt(r, "timeout_seconds", 15)
	}
	switch g.Kind {
	case guardrails.KindPII:
		c.Entities = r.Form["entities"]
	case guardrails.KindBlocklist:
		c.Categories = r.Form["categories"]
		c.Words = lines(r.FormValue("words"))
		c.Replacement = ui.FormStr(r, "bl_replacement")
	case guardrails.KindRegex:
		pats, reps := r.Form["pattern"], r.Form["pattern_replacement"]
		for i, p := range pats {
			if strings.TrimSpace(p) == "" {
				continue
			}
			pt := guardrails.Pattern{Pattern: strings.TrimSpace(p)}
			if i < len(reps) {
				pt.Replacement = reps[i]
			}
			c.Patterns = append(c.Patterns, pt)
		}
		c.Replacement = ui.FormStr(r, "re_replacement")
	case guardrails.KindMaxLength:
		c.MaxChars = ui.FormInt(r, "max_chars", 0)
	case guardrails.KindPromptInjection:
		c.Threshold = formFloat(r, "inj_threshold")
	case guardrails.KindCodeExecution:
		c.Languages = r.Form["languages"]
	case guardrails.KindToolPolicy:
		c.AllowTools = lines(r.FormValue("allow_tools"))
		c.DenyTools = lines(r.FormValue("deny_tools"))
	case guardrails.KindSemantic:
		modelBacked(ui.FormStr(r, "sem_model"))
		c.Examples = lines(r.FormValue("examples"))
		c.Threshold = formFloat(r, "sem_threshold")
	case guardrails.KindGuardModel:
		modelBacked(ui.FormStr(r, "gm_model"))
		c.Family = ui.FormStr(r, "family")
		c.Hazards = r.Form["hazards"]
		if fm, ok := guardrails.FamilyInfo(c.Family); ok {
			if fm.UsesThreshold {
				c.Threshold = formFloat(r, "gm_threshold")
			}
			if len(fm.Hazards) == 0 {
				c.Hazards = nil
			}
		}
		if c.Family == guardrails.FamilyQwen3Guard {
			c.StrictControversial = ui.FormBool(r, "strict_controversial")
		}
		if c.Family == guardrails.FamilyShieldGemma {
			c.Policy = ui.FormStr(r, "gm_policy")
		}
	case guardrails.KindLLMJudge:
		modelBacked(ui.FormStr(r, "judge_model"))
		c.Policy = ui.FormStr(r, "policy")
	}
	g.Config = c
}

func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func (h *H) create(w http.ResponseWriter, r *http.Request) {
	var g guardrails.Guardrail
	bind(r, &g)
	if err := h.eng.Save(r.Context(), &g); err != nil {
		h.d.Partial(w, r, 422, area, "guardrail-form", h.form(g, true, err.Error()))
		return
	}
	h.d.Audit(r, "create", "guardrail", g.ID, "Created guardrail "+g.Name, nil, g)
	ui.Done(w, "Guardrail "+g.Name+" created", refreshAll...)
}

func (h *H) load(w http.ResponseWriter, r *http.Request) (guardrails.Guardrail, bool) {
	g, err := h.eng.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		if errors.Is(err, guardrails.ErrNotFound) {
			ui.Fail(w, 404, "Guardrail not found")
		} else {
			ui.Fail(w, 500, err.Error())
		}
		return g, false
	}
	return g, true
}

func (h *H) editForm(w http.ResponseWriter, r *http.Request) {
	g, ok := h.load(w, r)
	if !ok {
		return
	}
	h.d.Partial(w, r, 200, area, "guardrail-form", h.form(g, false, ""))
}

func (h *H) update(w http.ResponseWriter, r *http.Request) {
	g, ok := h.load(w, r)
	if !ok {
		return
	}
	before := g
	bind(r, &g)
	g.Preset = before.Preset
	if err := h.eng.Save(r.Context(), &g); err != nil {
		h.d.Partial(w, r, 422, area, "guardrail-form", h.form(g, false, err.Error()))
		return
	}
	if before.Name != g.Name {
		h.renameRefs(r, before.Name, g.Name)
	}
	h.d.Audit(r, "update", "guardrail", g.ID, "Updated guardrail "+g.Name, before, g)
	ui.Done(w, "Guardrail saved", refreshAll...)
}

// renameRefs keeps key, team and policy references pointing at a renamed guardrail.
func (h *H) renameRefs(r *http.Request, from, to string) {
	ctx := r.Context()
	for _, t := range []string{"api_keys", "teams", "guardrail_policies"} {
		_, _ = h.d.Store.Pool.Exec(ctx, `UPDATE `+t+` SET guardrails = array_replace(guardrails, $1, $2) WHERE $1 = ANY(guardrails)`, from, to)
	}
	h.d.Changed()
	_ = h.eng.Reload(ctx)
}

func (h *H) toggle(w http.ResponseWriter, r *http.Request) {
	g, ok := h.load(w, r)
	if !ok {
		return
	}
	field := r.URL.Query().Get("field")
	var v bool
	switch field {
	case "enabled":
		v = !g.Enabled
	case "default_on":
		v = !g.DefaultOn
	default:
		ui.Fail(w, 400, "Unknown setting")
		return
	}
	if err := h.eng.SetFlag(r.Context(), g.ID, field, v); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	msg := flagMessage(g.Name, field, v)
	h.d.Audit(r, "update", "guardrail", g.ID, msg, map[string]bool{field: !v}, map[string]bool{field: v})
	ui.Toast(w, "success", msg)
	ui.Refresh(w, "refresh-guardrails")
	w.WriteHeader(http.StatusNoContent)
}

func flagMessage(name, field string, v bool) string {
	switch {
	case field == "enabled" && v:
		return "Enabled " + name
	case field == "enabled":
		return "Disabled " + name
	case v:
		return name + " now applies to every request"
	default:
		return name + " is no longer default-on"
	}
}

func (h *H) delete(w http.ResponseWriter, r *http.Request) {
	g, ok := h.load(w, r)
	if !ok {
		return
	}
	if err := h.eng.Delete(r.Context(), g.ID); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Audit(r, "delete", "guardrail", g.ID, "Deleted guardrail "+g.Name, g, nil)
	ui.Done(w, "Guardrail "+g.Name+" deleted", refreshAll...)
}

// --- test bench ---

type part struct {
	Text string
	Mask bool
}

type benchStep struct {
	guardrails.Step
	Via string // policies that pulled the guardrail in
}

type benchData struct {
	guardrails.TestResult
	Error   string
	Parts   []part
	Changed bool
	Kinds   map[string]KindInfo
	Ran     int
	Total   int
	Steps   []benchStep
	Phase   string
}

var maskToken = regexp.MustCompile(`\[[A-Z][A-Z0-9_ ]*\]`)

func highlight(s string) []part {
	var out []part
	last := 0
	for _, loc := range maskToken.FindAllStringIndex(s, -1) {
		if loc[0] > last {
			out = append(out, part{Text: s[last:loc[0]]})
		}
		out = append(out, part{Text: s[loc[0]:loc[1]], Mask: true})
		last = loc[1]
	}
	if last < len(s) {
		out = append(out, part{Text: s[last:]})
	}
	return out
}

func (h *H) test(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	names := r.Form["guardrails"]
	polNames := r.Form["policies"]
	text := r.FormValue("text")
	bd := benchData{Kinds: kindMap(), Phase: r.FormValue("phase")}
	via := map[string][]string{}
	if len(polNames) > 0 {
		pols, err := h.eng.ListPolicies(r.Context())
		if err != nil {
			bd.Error = err.Error()
		}
		for _, p := range pols {
			if !slices.Contains(polNames, p.Name) {
				continue
			}
			for _, g := range p.Guardrails {
				via[g] = append(via[g], p.Name)
				if !slices.Contains(names, g) {
					names = append(names, g)
				}
			}
		}
	}
	switch {
	case bd.Error != "":
	case len(names) == 0:
		bd.Error = "Select at least one policy or guardrail to run."
	case strings.TrimSpace(text) == "":
		bd.Error = "Paste some text to check."
	default:
		res, err := h.eng.Test(r.Context(), names, text, bd.Phase)
		if err != nil {
			bd.Error = err.Error()
		} else {
			bd.TestResult = res
			bd.Parts = highlight(res.Output)
			bd.Changed = res.Output != res.Input
			bd.Ran, bd.Total = len(res.Steps), len(names)
			for _, s := range res.Steps {
				bd.Steps = append(bd.Steps, benchStep{Step: s, Via: strings.Join(via[s.Guardrail], ", ")})
			}
		}
	}
	h.d.Partial(w, r, 200, area, "bench-result", bd)
}

// --- events ---

type eventsData struct {
	Events []guardrails.Event
	Range  string
}

func (h *H) events(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := guardrails.EventFilter{Guardrail: q.Get("guardrail"), Action: q.Get("action"), Phase: q.Get("phase"), Limit: 200}
	rng := q.Get("range")
	switch rng {
	case "1h":
		f.Since = time.Now().Add(-time.Hour)
	case "7d":
		f.Since = time.Now().Add(-7 * 24 * time.Hour)
	case "30d":
		f.Since = time.Now().Add(-30 * 24 * time.Hour)
	default:
		rng = "24h"
		f.Since = time.Now().Add(-24 * time.Hour)
	}
	evs, err := h.eng.Events(r.Context(), f)
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Partial(w, r, 200, area, "events-table", eventsData{Events: evs, Range: rng})
}
