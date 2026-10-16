package api

import (
	"net/http"
	"strings"

	"lemongate/internal/store"
)

// --- tags ---

func (h *H) listTags(w http.ResponseWriter, r *http.Request) {
	t, err := h.d.Store.ListTags(r.Context())
	if err != nil {
		storeErr(w, err, "tags")
		return
	}
	writeJSON(w, 200, list(t))
}

func (h *H) getTag(w http.ResponseWriter, r *http.Request) {
	t, err := h.d.Store.GetTag(r.Context(), param(r, "name"))
	if err != nil {
		storeErr(w, err, "tag")
		return
	}
	writeJSON(w, 200, t)
}

func (h *H) createTag(w http.ResponseWriter, r *http.Request) {
	var t store.Tag
	if !decode(w, r, &t) {
		return
	}
	t.Name = strings.TrimSpace(t.Name)
	if t.Name == "" {
		badRequest(w, "name is required")
		return
	}
	if !validPeriod(t.BudgetPeriod) {
		badRequest(w, "invalid budget_period")
		return
	}
	if _, err := h.d.Store.GetTag(r.Context(), t.Name); err == nil {
		storeErr(w, store.ErrConflict, "tag")
		return
	}
	if err := h.d.Store.UpsertTag(r.Context(), t); err != nil {
		storeErr(w, err, "tag")
		return
	}
	h.d.Changed()
	h.d.Audit(r, "create", "tag", t.Name, "Created tag "+t.Name+" via API", nil, t)
	t, _ = h.d.Store.GetTag(r.Context(), t.Name)
	writeJSON(w, 201, t)
}

func (h *H) updateTag(w http.ResponseWriter, r *http.Request) {
	t, err := h.d.Store.GetTag(r.Context(), param(r, "name"))
	if err != nil {
		storeErr(w, err, "tag")
		return
	}
	before := t
	if !decode(w, r, &t) {
		return
	}
	t.Name, t.Spend, t.CreatedAt = before.Name, before.Spend, before.CreatedAt
	if !validPeriod(t.BudgetPeriod) {
		badRequest(w, "invalid budget_period")
		return
	}
	if err := h.d.Store.UpsertTag(r.Context(), t); err != nil {
		storeErr(w, err, "tag")
		return
	}
	h.d.Changed()
	h.d.Audit(r, "update", "tag", t.Name, "Updated tag "+t.Name+" via API", before, t)
	t, _ = h.d.Store.GetTag(r.Context(), t.Name)
	writeJSON(w, 200, t)
}

func (h *H) deleteTag(w http.ResponseWriter, r *http.Request) {
	name := param(r, "name")
	if err := h.d.Store.DeleteTag(r.Context(), name); err != nil {
		storeErr(w, err, "tag")
		return
	}
	h.d.Changed()
	h.d.Audit(r, "delete", "tag", name, "Deleted tag "+name+" via API", nil, nil)
	writeJSON(w, 200, deleted(name))
}

// --- end users ---

func (h *H) listEndUsers(w http.ResponseWriter, r *http.Request) {
	e, err := h.d.Store.ListEndUsers(r.Context(), r.URL.Query().Get("q"))
	if err != nil {
		storeErr(w, err, "end users")
		return
	}
	writeJSON(w, 200, list(e))
}

func (h *H) getEndUser(w http.ResponseWriter, r *http.Request) {
	e, err := h.d.Store.GetEndUser(r.Context(), param(r, "id"))
	if err != nil {
		storeErr(w, err, "end user")
		return
	}
	writeJSON(w, 200, e)
}

func (h *H) createEndUser(w http.ResponseWriter, r *http.Request) {
	var e store.EndUser
	if !decode(w, r, &e) {
		return
	}
	e.ID = strings.TrimSpace(e.ID)
	if e.ID == "" {
		badRequest(w, "id is required")
		return
	}
	if !validPeriod(e.BudgetPeriod) {
		badRequest(w, "invalid budget_period")
		return
	}
	if _, err := h.d.Store.GetEndUser(r.Context(), e.ID); err == nil {
		storeErr(w, store.ErrConflict, "end user")
		return
	}
	if err := h.d.Store.UpsertEndUser(r.Context(), e); err != nil {
		storeErr(w, err, "end user")
		return
	}
	h.d.Changed()
	h.d.Audit(r, "create", "end_user", e.ID, "Created end user "+e.ID+" via API", nil, e)
	e, _ = h.d.Store.GetEndUser(r.Context(), e.ID)
	writeJSON(w, 201, e)
}

func (h *H) updateEndUser(w http.ResponseWriter, r *http.Request) {
	e, err := h.d.Store.GetEndUser(r.Context(), param(r, "id"))
	if err != nil {
		storeErr(w, err, "end user")
		return
	}
	before := e
	if !decode(w, r, &e) {
		return
	}
	e.ID, e.Spend, e.FirstSeenAt, e.LastSeenAt = before.ID, before.Spend, before.FirstSeenAt, before.LastSeenAt
	if !validPeriod(e.BudgetPeriod) {
		badRequest(w, "invalid budget_period")
		return
	}
	if err := h.d.Store.UpsertEndUser(r.Context(), e); err != nil {
		storeErr(w, err, "end user")
		return
	}
	h.d.Changed()
	h.d.Audit(r, "update", "end_user", e.ID, "Updated end user "+e.ID+" via API", before, e)
	e, _ = h.d.Store.GetEndUser(r.Context(), e.ID)
	writeJSON(w, 200, e)
}

func (h *H) deleteEndUser(w http.ResponseWriter, r *http.Request) {
	id := param(r, "id")
	if err := h.d.Store.DeleteEndUser(r.Context(), id); err != nil {
		storeErr(w, err, "end user")
		return
	}
	h.d.Changed()
	h.d.Audit(r, "delete", "end_user", id, "Deleted end user "+id+" via API", nil, nil)
	writeJSON(w, 200, deleted(id))
}

// --- budget presets ---

func (h *H) listPresets(w http.ResponseWriter, r *http.Request) {
	p, err := h.d.Store.ListBudgetPresets(r.Context())
	if err != nil {
		storeErr(w, err, "budget presets")
		return
	}
	writeJSON(w, 200, list(p))
}

func (h *H) getPreset(w http.ResponseWriter, r *http.Request) {
	p, err := h.d.Store.GetBudgetPreset(r.Context(), param(r, "id"))
	if err != nil {
		storeErr(w, err, "budget preset")
		return
	}
	writeJSON(w, 200, p)
}

func (h *H) presetByName(r *http.Request, name string) (store.BudgetPreset, bool) {
	all, _ := h.d.Store.ListBudgetPresets(r.Context())
	for _, p := range all {
		if p.Name == name {
			return p, true
		}
	}
	return store.BudgetPreset{}, false
}

func (h *H) createPreset(w http.ResponseWriter, r *http.Request) {
	var b store.BudgetPreset
	if !decode(w, r, &b) {
		return
	}
	b.ID, b.Name = "", strings.TrimSpace(b.Name)
	if b.Name == "" {
		badRequest(w, "name is required")
		return
	}
	if !validPeriod(b.BudgetPeriod) {
		badRequest(w, "invalid budget_period")
		return
	}
	if err := h.d.Store.SaveBudgetPreset(r.Context(), b); err != nil {
		storeErr(w, err, "budget preset")
		return
	}
	saved, _ := h.presetByName(r, b.Name)
	h.d.Audit(r, "create", "budget_preset", saved.ID, "Created budget preset "+b.Name+" via API", nil, saved)
	writeJSON(w, 201, saved)
}

func (h *H) updatePreset(w http.ResponseWriter, r *http.Request) {
	b, err := h.d.Store.GetBudgetPreset(r.Context(), param(r, "id"))
	if err != nil {
		storeErr(w, err, "budget preset")
		return
	}
	before := b
	if !decode(w, r, &b) {
		return
	}
	b.ID, b.CreatedAt = before.ID, before.CreatedAt
	b.Name = strings.TrimSpace(b.Name)
	if b.Name == "" {
		badRequest(w, "name cannot be empty")
		return
	}
	if !validPeriod(b.BudgetPeriod) {
		badRequest(w, "invalid budget_period")
		return
	}
	if err := h.d.Store.SaveBudgetPreset(r.Context(), b); err != nil {
		storeErr(w, err, "budget preset")
		return
	}
	h.d.Audit(r, "update", "budget_preset", b.ID, "Updated budget preset "+b.Name+" via API", before, b)
	b, _ = h.d.Store.GetBudgetPreset(r.Context(), b.ID)
	writeJSON(w, 200, b)
}

func (h *H) deletePreset(w http.ResponseWriter, r *http.Request) {
	b, err := h.d.Store.GetBudgetPreset(r.Context(), param(r, "id"))
	if err != nil {
		storeErr(w, err, "budget preset")
		return
	}
	if err := h.d.Store.DeleteBudgetPreset(r.Context(), b.ID); err != nil {
		storeErr(w, err, "budget preset")
		return
	}
	h.d.Audit(r, "delete", "budget_preset", b.ID, "Deleted budget preset "+b.Name+" via API", b, nil)
	writeJSON(w, 200, deleted(b.ID))
}
