package api

import (
	"net/http"
	"net/url"
	"slices"
	"strings"

	"lemongate/internal/secret"
	"lemongate/internal/store"
)

var validModes = []string{"chat", "completion", "embedding", "rerank", "audio"}

func validateDeployment(d *store.Deployment) string {
	d.Name, d.APIBase, d.UpstreamModel = strings.TrimSpace(d.Name), strings.TrimSpace(d.APIBase), strings.TrimSpace(d.UpstreamModel)
	if d.Name == "" || d.APIBase == "" || d.UpstreamModel == "" {
		return "name, api_base and upstream_model are required"
	}
	if u, err := url.Parse(d.APIBase); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "api_base must be an http(s) URL"
	}
	if d.Mode == "" {
		d.Mode = "chat"
	}
	if !slices.Contains(validModes, d.Mode) {
		return "mode must be one of " + strings.Join(validModes, ", ")
	}
	if d.Weight <= 0 {
		d.Weight = 1
	}
	if d.TimeoutSeconds <= 0 {
		d.TimeoutSeconds = 600
	}
	if d.InputCostPerM < 0 || d.OutputCostPerM < 0 {
		return "costs cannot be negative"
	}
	if d.CredentialID != nil && *d.CredentialID == "" {
		d.CredentialID = nil
	}
	return ""
}

func (h *H) listDeployments(w http.ResponseWriter, r *http.Request) {
	deps, err := h.d.Store.ListDeployments(r.Context())
	if err != nil {
		storeErr(w, err, "deployments")
		return
	}
	writeJSON(w, 200, list(deps))
}

func (h *H) getDeployment(w http.ResponseWriter, r *http.Request) {
	d, err := h.d.Store.GetDeployment(r.Context(), param(r, "id"))
	if err != nil {
		storeErr(w, err, "deployment")
		return
	}
	writeJSON(w, 200, d)
}

func (h *H) createDeployment(w http.ResponseWriter, r *http.Request) {
	d := store.Deployment{Mode: "chat", Weight: 1, TimeoutSeconds: 600, Enabled: true}
	if !decode(w, r, &d) {
		return
	}
	if msg := validateDeployment(&d); msg != "" {
		badRequest(w, "%s", msg)
		return
	}
	created, err := h.d.Store.CreateDeployment(r.Context(), d)
	if err != nil {
		storeErr(w, err, "deployment")
		return
	}
	h.d.ReloadModels(r.Context())
	h.d.Audit(r, "create", "deployment", created.ID, "Created deployment "+created.Name+" ("+created.APIBase+") via API", nil, created)
	writeJSON(w, 201, created)
}

func (h *H) updateDeployment(w http.ResponseWriter, r *http.Request) {
	d, err := h.d.Store.GetDeployment(r.Context(), param(r, "id"))
	if err != nil {
		storeErr(w, err, "deployment")
		return
	}
	before := d
	if !decode(w, r, &d) {
		return
	}
	d.ID, d.CreatedAt = before.ID, before.CreatedAt
	if msg := validateDeployment(&d); msg != "" {
		badRequest(w, "%s", msg)
		return
	}
	if err := h.d.Store.UpdateDeployment(r.Context(), d); err != nil {
		storeErr(w, err, "deployment")
		return
	}
	h.d.ReloadModels(r.Context())
	h.d.Audit(r, "update", "deployment", d.ID, "Updated deployment "+d.Name+" via API", before, d)
	d, _ = h.d.Store.GetDeployment(r.Context(), d.ID)
	writeJSON(w, 200, d)
}

func (h *H) deleteDeployment(w http.ResponseWriter, r *http.Request) {
	d, err := h.d.Store.GetDeployment(r.Context(), param(r, "id"))
	if err != nil {
		storeErr(w, err, "deployment")
		return
	}
	if err := h.d.Store.DeleteDeployment(r.Context(), d.ID); err != nil {
		storeErr(w, err, "deployment")
		return
	}
	h.d.ReloadModels(r.Context())
	h.d.Audit(r, "delete", "deployment", d.ID, "Deleted deployment "+d.Name+" via API", d, nil)
	writeJSON(w, 200, deleted(d.ID))
}

// --- aliases ---

func (h *H) listAliases(w http.ResponseWriter, r *http.Request) {
	a, err := h.d.Store.ListAliases(r.Context())
	if err != nil {
		storeErr(w, err, "aliases")
		return
	}
	writeJSON(w, 200, list(a))
}

func (h *H) upsertAlias(w http.ResponseWriter, r *http.Request) {
	var a store.Alias
	if !decode(w, r, &a) {
		return
	}
	a.Alias, a.Target = strings.TrimSpace(a.Alias), strings.TrimSpace(a.Target)
	if a.Alias == "" || a.Target == "" {
		badRequest(w, "alias and target are required")
		return
	}
	if a.Alias == a.Target {
		badRequest(w, "an alias cannot point to itself")
		return
	}
	if err := h.d.Store.UpsertAlias(r.Context(), a.Alias, a.Target); err != nil {
		storeErr(w, err, "alias")
		return
	}
	h.d.ReloadModels(r.Context())
	h.d.Audit(r, "upsert", "alias", a.Alias, "Set alias "+a.Alias+" → "+a.Target+" via API", nil, a)
	writeJSON(w, 200, map[string]string{"alias": a.Alias, "target": a.Target})
}

func (h *H) deleteAlias(w http.ResponseWriter, r *http.Request) {
	name := param(r, "alias")
	if err := h.d.Store.DeleteAlias(r.Context(), name); err != nil {
		storeErr(w, err, "alias")
		return
	}
	h.d.ReloadModels(r.Context())
	h.d.Audit(r, "delete", "alias", name, "Deleted alias "+name+" via API", nil, nil)
	writeJSON(w, 200, deleted(name))
}

// --- access groups ---

func (h *H) listAccessGroups(w http.ResponseWriter, r *http.Request) {
	g, err := h.d.Store.ListAccessGroups(r.Context())
	if err != nil {
		storeErr(w, err, "access groups")
		return
	}
	writeJSON(w, 200, list(g))
}

func (h *H) findAccessGroup(r *http.Request, name string) (store.AccessGroup, bool) {
	groups, _ := h.d.Store.ListAccessGroups(r.Context())
	for _, g := range groups {
		if g.Name == name {
			return g, true
		}
	}
	return store.AccessGroup{}, false
}

func (h *H) saveAccessGroup(w http.ResponseWriter, r *http.Request, g store.AccessGroup, before any) {
	g.Name = strings.TrimSpace(g.Name)
	if g.Name == "" {
		badRequest(w, "name is required")
		return
	}
	if err := h.d.Store.UpsertAccessGroup(r.Context(), g); err != nil {
		storeErr(w, err, "access group")
		return
	}
	h.d.ReloadModels(r.Context())
	h.d.Audit(r, "upsert", "access_group", g.Name, "Saved access group "+g.Name+" via API", before, g)
	saved, _ := h.findAccessGroup(r, g.Name)
	writeJSON(w, 200, saved)
}

func (h *H) upsertAccessGroup(w http.ResponseWriter, r *http.Request) {
	var g store.AccessGroup
	if !decode(w, r, &g) {
		return
	}
	h.saveAccessGroup(w, r, g, nil)
}

func (h *H) updateAccessGroup(w http.ResponseWriter, r *http.Request) {
	g, ok := h.findAccessGroup(r, param(r, "name"))
	if !ok {
		notFound(w, "access group")
		return
	}
	before := g
	if !decode(w, r, &g) {
		return
	}
	g.Name = before.Name
	h.saveAccessGroup(w, r, g, before)
}

func (h *H) deleteAccessGroup(w http.ResponseWriter, r *http.Request) {
	name := param(r, "name")
	if err := h.d.Store.DeleteAccessGroup(r.Context(), name); err != nil {
		storeErr(w, err, "access group")
		return
	}
	h.d.ReloadModels(r.Context())
	h.d.Audit(r, "delete", "access_group", name, "Deleted access group "+name+" via API", nil, nil)
	writeJSON(w, 200, deleted(name))
}

// --- fallbacks ---

func (h *H) listFallbacks(w http.ResponseWriter, r *http.Request) {
	f, err := h.d.Store.ListFallbacks(r.Context())
	if err != nil {
		storeErr(w, err, "fallbacks")
		return
	}
	writeJSON(w, 200, list(f))
}

func (h *H) upsertFallback(w http.ResponseWriter, r *http.Request) {
	var f store.Fallback
	if !decode(w, r, &f) {
		return
	}
	f.Model = strings.TrimSpace(f.Model)
	if f.Kind == "" {
		f.Kind = "general"
	}
	if f.Model == "" || len(store.CleanList(f.Targets)) == 0 {
		badRequest(w, "model and at least one target are required")
		return
	}
	if f.Kind != "general" && f.Kind != "context" {
		badRequest(w, "kind must be general or context")
		return
	}
	if slices.Contains(f.Targets, f.Model) {
		badRequest(w, "a model cannot fall back to itself")
		return
	}
	if err := h.d.Store.UpsertFallback(r.Context(), f); err != nil {
		storeErr(w, err, "fallback")
		return
	}
	h.d.ReloadModels(r.Context())
	h.d.Audit(r, "upsert", "fallback", f.Model, "Set "+f.Kind+" fallbacks for "+f.Model+" via API", nil, f)
	f.Targets = store.CleanList(f.Targets)
	writeJSON(w, 200, f)
}

func (h *H) deleteFallback(w http.ResponseWriter, r *http.Request) {
	model, kind := param(r, "model"), r.URL.Query().Get("kind")
	if kind == "" {
		kind = "general"
	}
	if err := h.d.Store.DeleteFallback(r.Context(), model, kind); err != nil {
		storeErr(w, err, "fallback")
		return
	}
	h.d.ReloadModels(r.Context())
	h.d.Audit(r, "delete", "fallback", model, "Deleted "+kind+" fallbacks for "+model+" via API", nil, nil)
	writeJSON(w, 200, deleted(model))
}

// --- credentials ---

type credentialInput struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	Secret      *string `json:"secret"`
}

func (h *H) listCredentials(w http.ResponseWriter, r *http.Request) {
	c, err := h.d.Store.ListCredentials(r.Context())
	if err != nil {
		storeErr(w, err, "credentials")
		return
	}
	writeJSON(w, 200, list(c))
}

func (h *H) getCredential(w http.ResponseWriter, r *http.Request) {
	c, err := h.d.Store.GetCredential(r.Context(), param(r, "id"))
	if err != nil {
		storeErr(w, err, "credential")
		return
	}
	writeJSON(w, 200, c)
}

func (h *H) createCredential(w http.ResponseWriter, r *http.Request) {
	var in credentialInput
	if !decode(w, r, &in) {
		return
	}
	c := store.Credential{}
	if in.Name != nil {
		c.Name = strings.TrimSpace(*in.Name)
	}
	if in.Description != nil {
		c.Description = *in.Description
	}
	if c.Name == "" || in.Secret == nil || *in.Secret == "" {
		badRequest(w, "name and secret are required")
		return
	}
	enc, err := h.d.Box.SealString(*in.Secret)
	if err != nil {
		storeErr(w, err, "credential")
		return
	}
	c.SecretEnc, c.Hint = enc, secret.Hint(*in.Secret)
	created, err := h.d.Store.CreateCredential(r.Context(), c)
	if err != nil {
		storeErr(w, err, "credential")
		return
	}
	h.d.ReloadModels(r.Context())
	h.d.Audit(r, "create", "credential", created.ID, "Created credential "+created.Name+" via API", nil, created)
	writeJSON(w, 201, created)
}

func (h *H) updateCredential(w http.ResponseWriter, r *http.Request) {
	c, err := h.d.Store.GetCredential(r.Context(), param(r, "id"))
	if err != nil {
		storeErr(w, err, "credential")
		return
	}
	before := c
	var in credentialInput
	if !decode(w, r, &in) {
		return
	}
	if in.Name != nil {
		c.Name = strings.TrimSpace(*in.Name)
	}
	if in.Description != nil {
		c.Description = *in.Description
	}
	if c.Name == "" {
		badRequest(w, "name cannot be empty")
		return
	}
	c.SecretEnc = nil
	rotated := in.Secret != nil && *in.Secret != ""
	if rotated {
		enc, err := h.d.Box.SealString(*in.Secret)
		if err != nil {
			storeErr(w, err, "credential")
			return
		}
		c.SecretEnc, c.Hint = enc, secret.Hint(*in.Secret)
	}
	if err := h.d.Store.UpdateCredential(r.Context(), c); err != nil {
		storeErr(w, err, "credential")
		return
	}
	h.d.ReloadModels(r.Context())
	summary := "Updated credential " + c.Name + " via API"
	if rotated {
		summary += " (secret rotated)"
	}
	h.d.Audit(r, "update", "credential", c.ID, summary, before, c)
	c, _ = h.d.Store.GetCredential(r.Context(), c.ID)
	writeJSON(w, 200, c)
}

func (h *H) deleteCredential(w http.ResponseWriter, r *http.Request) {
	c, err := h.d.Store.GetCredential(r.Context(), param(r, "id"))
	if err != nil {
		storeErr(w, err, "credential")
		return
	}
	if err := h.d.Store.DeleteCredential(r.Context(), c.ID); err != nil {
		storeErr(w, err, "credential")
		return
	}
	h.d.ReloadModels(r.Context())
	h.d.Audit(r, "delete", "credential", c.ID, "Deleted credential "+c.Name+" via API", c, nil)
	writeJSON(w, 200, deleted(c.ID))
}
