package api

import (
	"encoding/json"
	"net/http"
	"slices"
	"time"

	"lemongate/internal/auth"
	"lemongate/internal/store"
)

func (h *H) me(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	out := map[string]any{"kind": p.Kind, "role": p.Role, "label": p.Label(), "read_only": p.ReadOnly()}
	if p.User != nil {
		out["user"] = p.User
	}
	if p.Team != nil {
		out["team"] = p.Team
	}
	if p.Key != nil {
		out["key"] = p.Key
	}
	if p.Memberships != nil {
		out["memberships"] = p.Memberships
	}
	writeJSON(w, 200, out)
}

// keyInput is the create/update body: a key plus convenience fields.
type keyInput struct {
	*store.Key
	ExpiresIn *string `json:"expires_in"`
}

var validScopes = []string{"inference", "management", "admin"}

func validPeriod(p string) bool {
	if slices.Contains(store.PeriodOptions, p) {
		return true
	}
	_, ok := store.ParseDuration(p)
	return ok
}

// applyKey validates k after a body was decoded onto it. before is the stored key
// (zero for creates); non-admins cannot change ownership or scope.
func applyKey(p *auth.Principal, k *store.Key, before *store.Key, expiresIn *string) string {
	if expiresIn != nil {
		switch *expiresIn {
		case "", "never":
			k.ExpiresAt = nil
		default:
			d, ok := store.ParseDuration(*expiresIn)
			if !ok {
				return "expires_in must be a duration such as 30d or 12h"
			}
			t := time.Now().Add(d)
			k.ExpiresAt = &t
		}
	}
	if k.Scope == "" {
		k.Scope = "inference"
	}
	if !slices.Contains(validScopes, k.Scope) {
		return "scope must be inference, management or admin"
	}
	if !validPeriod(k.BudgetPeriod) {
		return "budget_period must be daily, weekly, monthly or a duration such as 7d"
	}
	if !p.IsAdmin() {
		if before != nil {
			if k.Scope != before.Scope || store.Deref(k.UserID) != store.Deref(before.UserID) {
				return "only admins can change a key's owner or scope"
			}
		} else {
			if k.Scope != "inference" {
				return "only admins can create management or admin keys"
			}
			if k.UserID != nil && *k.UserID != p.UserID() {
				return "you can only create keys for yourself"
			}
		}
		if err := p.CheckKeyEdit(before, k); err != nil {
			return err.Error()
		}
		if k.UserID == nil && k.TeamID == nil {
			if p.User == nil {
				return "user_id or team_id is required"
			}
			k.UserID = &p.User.ID
		}
	}
	return ""
}

// canCreateKeys mirrors the console: admins, team admins, or members when allowed.
func (h *H) canCreateKeys(p *auth.Principal) bool {
	if p.ReadOnly() {
		return false
	}
	if p.IsAdmin() || h.d.Settings.Current().General.AllowMemberKeys {
		return true
	}
	for _, m := range p.Memberships {
		if m.Role == auth.TeamRoleAdmin {
			return true
		}
	}
	return false
}

func (h *H) listKeys(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	q := r.URL.Query()
	f := store.KeyFilter{Search: q.Get("q"), UserID: q.Get("user_id"), TeamID: q.Get("team_id"), Deleted: q.Get("deleted") == "true" || q.Get("deleted") == "1"}
	keys, err := h.d.Store.ListKeys(r.Context(), f)
	if err != nil {
		storeErr(w, err, "keys")
		return
	}
	if !p.CanViewAll() {
		keys = slices.DeleteFunc(keys, func(k store.Key) bool { return !p.CanViewKey(k) })
	}
	writeJSON(w, 200, list(keys))
}

func (h *H) loadKey(w http.ResponseWriter, r *http.Request, manage bool) (store.Key, bool) {
	p := principal(r)
	k, err := h.d.Store.GetKey(r.Context(), param(r, "id"))
	if err != nil {
		storeErr(w, err, "key")
		return k, false
	}
	if !p.CanViewKey(k) {
		notFound(w, "key")
		return k, false
	}
	if manage && !p.CanManageKey(k) {
		forbidden(w, "you cannot manage this key")
		return k, false
	}
	return k, true
}

func (h *H) getKey(w http.ResponseWriter, r *http.Request) {
	if k, ok := h.loadKey(w, r, false); ok {
		writeJSON(w, 200, k)
	}
}

type keyCreated struct {
	store.Key
	Plain string `json:"key"`
}

func (h *H) createKey(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if !h.canCreateKeys(p) {
		forbidden(w, "you are not allowed to create keys")
		return
	}
	k := store.Key{Scope: "inference", MaxBudget: h.d.Settings.Current().General.DefaultKeyBudget}
	in := keyInput{Key: &k}
	if !decode(w, r, &in) {
		return
	}
	if msg := applyKey(p, &k, nil, in.ExpiresIn); msg != "" {
		badRequest(w, "%s", msg)
		return
	}
	if in.ExpiresIn == nil && k.ExpiresAt == nil {
		if d, ok := store.ParseDuration(h.d.Settings.Current().General.DefaultKeyDuration); ok {
			t := time.Now().Add(d)
			k.ExpiresAt = &t
		}
	}
	plain, hash, hint := auth.NewKey()
	k.KeyHash, k.KeyHint, k.CreatedBy = hash, hint, p.Label()+" (api)"
	created, err := h.d.Store.CreateKey(r.Context(), k)
	if err != nil {
		storeErr(w, err, "key")
		return
	}
	h.d.Changed()
	h.d.Audit(r, "create", "key", created.ID, "Created key "+created.Label()+" via API", nil, created)
	writeJSON(w, 201, keyCreated{Key: created, Plain: plain})
}

func (h *H) updateKey(w http.ResponseWriter, r *http.Request) {
	k, ok := h.loadKey(w, r, true)
	if !ok {
		return
	}
	before := k
	in := keyInput{Key: &k}
	if !decode(w, r, &in) {
		return
	}
	// Immutable fields.
	k.ID, k.KeyHash, k.KeyHint, k.Spend, k.CreatedAt, k.CreatedBy, k.DeletedAt = before.ID, before.KeyHash, before.KeyHint, before.Spend, before.CreatedAt, before.CreatedBy, before.DeletedAt
	if msg := applyKey(principal(r), &k, &before, in.ExpiresIn); msg != "" {
		badRequest(w, "%s", msg)
		return
	}
	if err := h.d.Store.UpdateKey(r.Context(), k); err != nil {
		storeErr(w, err, "key")
		return
	}
	h.d.Changed()
	h.d.Audit(r, "update", "key", k.ID, "Updated key "+k.Label()+" via API", before, k)
	h.respondKey(w, r, k.ID)
}

func (h *H) respondKey(w http.ResponseWriter, r *http.Request, id string) {
	k, err := h.d.Store.GetKey(r.Context(), id)
	if err != nil {
		storeErr(w, err, "key")
		return
	}
	writeJSON(w, 200, k)
}

func (h *H) deleteKey(w http.ResponseWriter, r *http.Request) {
	k, ok := h.loadKey(w, r, true)
	if !ok {
		return
	}
	if err := h.d.Store.SoftDeleteKey(r.Context(), k.ID); err != nil {
		storeErr(w, err, "key")
		return
	}
	h.d.Changed()
	h.d.Audit(r, "delete", "key", k.ID, "Deleted key "+k.Label()+" via API", k, nil)
	writeJSON(w, 200, deleted(k.ID))
}

func (h *H) regenerateKey(w http.ResponseWriter, r *http.Request) {
	k, ok := h.loadKey(w, r, true)
	if !ok {
		return
	}
	plain, hash, hint := auth.NewKey()
	if err := h.d.Store.RotateKey(r.Context(), k.ID, hash, hint); err != nil {
		storeErr(w, err, "key")
		return
	}
	h.d.Changed()
	h.d.Audit(r, "rotate", "key", k.ID, "Regenerated key "+k.Label()+" via API", nil, nil)
	k, _ = h.d.Store.GetKey(r.Context(), k.ID)
	writeJSON(w, 200, keyCreated{Key: k, Plain: plain})
}

func (h *H) blockKey(blocked bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		k, ok := h.loadKey(w, r, true)
		if !ok {
			return
		}
		if !blocked && k.Blocked && !principal(r).CanUnblockKey(k) {
			forbidden(w, "only an admin can unblock this key")
			return
		}
		if err := h.d.Store.SetKeyBlocked(r.Context(), k.ID, blocked); err != nil {
			storeErr(w, err, "key")
			return
		}
		h.d.Changed()
		action, verb := "unblock", "Unblocked"
		if blocked {
			action, verb = "block", "Blocked"
		}
		h.d.Audit(r, action, "key", k.ID, verb+" key "+k.Label()+" via API", nil, nil)
		h.respondKey(w, r, k.ID)
	}
}

type deletedResp struct {
	ID      string `json:"id"`
	Deleted bool   `json:"deleted"`
}

func deleted(id string) deletedResp { return deletedResp{ID: id, Deleted: true} }

// mustJSON is used for audit snapshots of raw rows.
func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
