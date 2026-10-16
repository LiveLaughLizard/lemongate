package guardrailsui

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/go-chi/chi/v5"

	"lemongate/internal/auth"
	"lemongate/internal/guardrails"
	"lemongate/internal/ui"
)

// PolicyRefs counts the active keys and teams that reference each policy by name.
type PolicyRefs struct{ Keys, Teams int }

// PolicyUsage returns policy name -> key/team reference counts in one query.
func PolicyUsage(ctx context.Context, d *ui.Deps) map[string]PolicyRefs {
	out := map[string]PolicyRefs{}
	rows, err := d.Store.Pool.Query(ctx, `SELECT p, sum(k)::int, sum(t)::int FROM (
		SELECT unnest(policies) AS p, 1 AS k, 0 AS t FROM api_keys WHERE deleted_at IS NULL
		UNION ALL SELECT unnest(policies), 0, 1 FROM teams WHERE deleted_at IS NULL) x GROUP BY p`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var r PolicyRefs
		if rows.Scan(&name, &r.Keys, &r.Teams) == nil {
			out[name] = r
		}
	}
	return out
}

type chip struct {
	Name    string
	Kind    KindInfo
	Missing bool
	Enabled bool
}

type policyRow struct {
	guardrails.Policy
	Chips       []chip
	Refs        PolicyRefs
	PresetTitle string
}

type policyTableData struct {
	Rows    []policyRow
	CanEdit bool
}

func (h *H) policyTable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pols, err := h.eng.ListPolicies(ctx)
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	list, err := h.eng.List(ctx)
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	byName := map[string]guardrails.Guardrail{}
	for _, g := range list {
		byName[g.Name] = g
	}
	usage := PolicyUsage(ctx, h.d)
	td := policyTableData{CanEdit: auth.FromContext(ctx).IsAdmin()}
	for _, p := range pols {
		pr := policyRow{Policy: p, Refs: usage[p.Name]}
		if ps, ok := guardrails.PresetByID(p.Preset); ok {
			pr.PresetTitle = ps.Title
		}
		for _, n := range p.Guardrails {
			g, ok := byName[n]
			pr.Chips = append(pr.Chips, chip{Name: n, Kind: Kind(g.Kind), Missing: !ok, Enabled: g.Enabled})
		}
		td.Rows = append(td.Rows, pr)
	}
	h.d.Partial(w, r, 200, area, "policies-table", td)
}

type policyFormData struct {
	P          guardrails.Policy
	IsNew      bool
	Error      string
	Guardrails []guardrails.Guardrail
	Kinds      map[string]KindInfo
}

func (h *H) policyForm(ctx context.Context, p guardrails.Policy, isNew bool, errMsg string) policyFormData {
	list, _ := h.eng.List(ctx)
	if p.Guardrails == nil {
		p.Guardrails = []string{}
	}
	return policyFormData{P: p, IsNew: isNew, Error: errMsg, Guardrails: list, Kinds: kindMap()}
}

func bindPolicy(r *http.Request, p *guardrails.Policy) {
	_ = r.ParseForm()
	p.Name = ui.FormStr(r, "name")
	p.Description = ui.FormStr(r, "description")
	p.Guardrails = r.Form["guardrails"]
	p.DefaultOn = ui.FormBool(r, "default_on")
	p.Enabled = ui.FormBool(r, "enabled")
}

func (h *H) newPolicy(w http.ResponseWriter, r *http.Request) {
	h.d.Partial(w, r, 200, area, "policy-form", h.policyForm(r.Context(), guardrails.Policy{Enabled: true}, true, ""))
}

func (h *H) createPolicy(w http.ResponseWriter, r *http.Request) {
	var p guardrails.Policy
	bindPolicy(r, &p)
	if err := h.eng.SavePolicy(r.Context(), &p); err != nil {
		h.d.Partial(w, r, 422, area, "policy-form", h.policyForm(r.Context(), p, true, policyErr(err)))
		return
	}
	h.d.Changed()
	h.d.Audit(r, "create", "guardrail_policy", p.ID, "Created guardrail policy "+p.Name, nil, p)
	ui.Done(w, "Policy "+p.Name+" created", refreshAll...)
}

func policyErr(err error) string {
	if errors.Is(err, guardrails.ErrConflict) {
		return "a policy with this name already exists"
	}
	return err.Error()
}

func (h *H) loadPolicy(w http.ResponseWriter, r *http.Request) (guardrails.Policy, bool) {
	p, err := h.eng.GetPolicy(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		if errors.Is(err, guardrails.ErrNotFound) {
			ui.Fail(w, 404, "Policy not found")
		} else {
			ui.Fail(w, 500, err.Error())
		}
		return p, false
	}
	return p, true
}

func (h *H) editPolicy(w http.ResponseWriter, r *http.Request) {
	p, ok := h.loadPolicy(w, r)
	if !ok {
		return
	}
	h.d.Partial(w, r, 200, area, "policy-form", h.policyForm(r.Context(), p, false, ""))
}

func (h *H) updatePolicy(w http.ResponseWriter, r *http.Request) {
	p, ok := h.loadPolicy(w, r)
	if !ok {
		return
	}
	before := p
	bindPolicy(r, &p)
	if err := h.eng.SavePolicy(r.Context(), &p); err != nil {
		h.d.Partial(w, r, 422, area, "policy-form", h.policyForm(r.Context(), p, false, policyErr(err)))
		return
	}
	h.d.Changed()
	h.d.Audit(r, "update", "guardrail_policy", p.ID, "Updated guardrail policy "+p.Name, before, p)
	ui.Done(w, "Policy saved", refreshAll...)
}

func (h *H) togglePolicy(w http.ResponseWriter, r *http.Request) {
	p, ok := h.loadPolicy(w, r)
	if !ok {
		return
	}
	field := r.URL.Query().Get("field")
	var v bool
	switch field {
	case "enabled":
		v = !p.Enabled
	case "default_on":
		v = !p.DefaultOn
	default:
		ui.Fail(w, 400, "Unknown setting")
		return
	}
	if err := h.eng.SetPolicyFlag(r.Context(), p.ID, field, v); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Changed()
	msg := flagMessage("Policy "+p.Name, field, v)
	h.d.Audit(r, "update", "guardrail_policy", p.ID, msg, map[string]bool{field: !v}, map[string]bool{field: v})
	ui.Toast(w, "success", msg)
	ui.Refresh(w, "refresh-policies")
	ui.Refresh(w, "refresh-presets")
	w.WriteHeader(http.StatusNoContent)
}

type deletePolicyData struct {
	P         guardrails.Policy
	Exclusive []string // guardrails used by no other policy
	Shared    []string
	Refs      PolicyRefs
}

// exclusiveGuardrails splits a policy's guardrails into those no other policy uses and the rest.
func (h *H) exclusiveGuardrails(ctx context.Context, p guardrails.Policy) (excl, shared []string) {
	pols, _ := h.eng.ListPolicies(ctx)
	for _, g := range p.Guardrails {
		used := slices.ContainsFunc(pols, func(o guardrails.Policy) bool { return o.ID != p.ID && slices.Contains(o.Guardrails, g) })
		if used {
			shared = append(shared, g)
		} else {
			excl = append(excl, g)
		}
	}
	return excl, shared
}

func (h *H) confirmDeletePolicy(w http.ResponseWriter, r *http.Request) {
	p, ok := h.loadPolicy(w, r)
	if !ok {
		return
	}
	excl, shared := h.exclusiveGuardrails(r.Context(), p)
	h.d.Partial(w, r, 200, area, "policy-delete", deletePolicyData{P: p, Exclusive: excl, Shared: shared, Refs: PolicyUsage(r.Context(), h.d)[p.Name]})
}

func (h *H) deletePolicy(w http.ResponseWriter, r *http.Request) {
	p, ok := h.loadPolicy(w, r)
	if !ok {
		return
	}
	_ = r.ParseForm()
	withG := ui.FormBool(r, "with_guardrails")
	if err := h.eng.DeletePolicy(r.Context(), p.ID, withG); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Changed()
	summary := "Deleted guardrail policy " + p.Name
	if withG {
		summary += " and its guardrails"
	}
	h.d.Audit(r, "delete", "guardrail_policy", p.ID, summary, p, nil)
	ui.Done(w, "Policy "+p.Name+" deleted", refreshAll...)
}
