// Package credentials manages named upstream secrets (encrypted at rest) that
// deployments, MCP servers and pass-through routes reference.
package credentials

import (
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"

	"lemongate/internal/auth"
	"lemongate/internal/secret"
	"lemongate/internal/store"
	"lemongate/internal/ui"
)

const area = "credentials"

type H struct{ d *ui.Deps }

// Mount registers routes for this area on the session-protected router.
func Mount(r chi.Router, d *ui.Deps) {
	h := &H{d}
	r.Group(func(r chi.Router) {
		r.Use(ui.AdminWrites)
		r.Get("/ui/credentials", h.index)
		r.Get("/ui/credentials/table", h.table)
		r.Get("/ui/credentials/new", h.newForm)
		r.Post("/ui/credentials", h.create)
		r.Get("/ui/credentials/{id}/edit", h.editForm)
		r.Get("/ui/credentials/{id}/rotate", h.rotateForm)
		r.Get("/ui/credentials/{id}/usage", h.usage)
		r.Post("/ui/credentials/{id}", h.update)
		r.Post("/ui/credentials/{id}/rotate", h.rotate)
		r.Post("/ui/credentials/{id}/delete", h.delete)
	})
}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

func (h *H) index(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	h.d.Render(w, r, "credentials/index", "credentials", "Credentials", map[string]any{"CanEdit": p.IsAdmin()})
}

type tableData struct {
	Creds   []store.Credential
	CanEdit bool
	Search  string
}

func (h *H) table(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	list, err := h.d.Store.ListCredentials(r.Context())
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	q := strings.ToLower(ui.FormStr(r, "q"))
	if q != "" {
		var out []store.Credential
		for _, c := range list {
			if strings.Contains(strings.ToLower(c.Name+" "+c.Description), q) {
				out = append(out, c)
			}
		}
		list = out
	}
	h.d.Partial(w, r, 200, area, "cred-table", tableData{Creds: list, CanEdit: p.IsAdmin(), Search: q})
}

type formData struct {
	Cred   store.Credential
	IsNew  bool
	Rotate bool
	Error  string
}

func (h *H) newForm(w http.ResponseWriter, r *http.Request) {
	h.d.Partial(w, r, 200, area, "cred-form", formData{IsNew: true})
}

func (h *H) load(w http.ResponseWriter, r *http.Request) (store.Credential, bool) {
	c, err := h.d.Store.GetCredential(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		ui.Fail(w, 404, "Credential not found")
		return c, false
	}
	return c, true
}

func (h *H) editForm(w http.ResponseWriter, r *http.Request) {
	c, ok := h.load(w, r)
	if !ok {
		return
	}
	h.d.Partial(w, r, 200, area, "cred-form", formData{Cred: c})
}

func (h *H) rotateForm(w http.ResponseWriter, r *http.Request) {
	c, ok := h.load(w, r)
	if !ok {
		return
	}
	h.d.Partial(w, r, 200, area, "cred-form", formData{Cred: c, Rotate: true})
}

func (h *H) bind(r *http.Request, c *store.Credential, requireSecret bool) error {
	_ = r.ParseForm()
	c.Name = ui.FormStr(r, "name")
	c.Description = ui.FormStr(r, "description")
	if !nameRe.MatchString(c.Name) {
		return errors.New("name must be 1-63 characters: letters, digits, dot, dash or underscore")
	}
	sec := r.FormValue("secret")
	sec = strings.TrimSpace(sec)
	if sec == "" {
		if requireSecret {
			return errors.New("secret value is required")
		}
		c.SecretEnc = nil
		return nil
	}
	enc, err := h.d.Box.SealString(sec)
	if err != nil {
		return errors.New("could not encrypt the secret: " + err.Error())
	}
	c.SecretEnc, c.Hint = enc, secret.Hint(sec)
	return nil
}

// redacted is what we record in the audit log (never the secret).
func redacted(c store.Credential) map[string]any {
	return map[string]any{"id": c.ID, "name": c.Name, "description": c.Description, "hint": c.Hint}
}

func (h *H) create(w http.ResponseWriter, r *http.Request) {
	var c store.Credential
	if err := h.bind(r, &c, true); err != nil {
		h.d.Partial(w, r, 422, area, "cred-form", formData{Cred: c, IsNew: true, Error: err.Error()})
		return
	}
	created, err := h.d.Store.CreateCredential(r.Context(), c)
	if err != nil {
		msg := err.Error()
		if errors.Is(err, store.ErrConflict) {
			msg = "a credential with that name already exists"
		}
		h.d.Partial(w, r, 422, area, "cred-form", formData{Cred: c, IsNew: true, Error: msg})
		return
	}
	h.d.Audit(r, "create", "credential", created.ID, "Created credential "+created.Name, nil, redacted(created))
	ui.Done(w, "Credential saved", "refresh-credentials")
}

func (h *H) update(w http.ResponseWriter, r *http.Request) {
	c, ok := h.load(w, r)
	if !ok {
		return
	}
	before := redacted(c)
	if err := h.bind(r, &c, false); err != nil {
		h.d.Partial(w, r, 422, area, "cred-form", formData{Cred: c, Error: err.Error()})
		return
	}
	rotated := c.SecretEnc != nil
	if err := h.d.Store.UpdateCredential(r.Context(), c); err != nil {
		msg := err.Error()
		if errors.Is(err, store.ErrConflict) {
			msg = "a credential with that name already exists"
		}
		h.d.Partial(w, r, 422, area, "cred-form", formData{Cred: c, Error: msg})
		return
	}
	h.d.ReloadModels(r.Context())
	summary := "Updated credential " + c.Name
	if rotated {
		summary += " (secret rotated)"
	}
	h.d.Audit(r, "update", "credential", c.ID, summary, before, redacted(c))
	ui.Done(w, "Credential updated", "refresh-credentials")
}

func (h *H) rotate(w http.ResponseWriter, r *http.Request) {
	c, ok := h.load(w, r)
	if !ok {
		return
	}
	before := redacted(c)
	_ = r.ParseForm()
	sec := strings.TrimSpace(r.FormValue("secret"))
	if sec == "" {
		h.d.Partial(w, r, 422, area, "cred-form", formData{Cred: c, Rotate: true, Error: "Enter the new secret value."})
		return
	}
	enc, err := h.d.Box.SealString(sec)
	if err != nil {
		h.d.Partial(w, r, 422, area, "cred-form", formData{Cred: c, Rotate: true, Error: err.Error()})
		return
	}
	c.SecretEnc, c.Hint = enc, secret.Hint(sec)
	if err := h.d.Store.UpdateCredential(r.Context(), c); err != nil {
		h.d.Partial(w, r, 422, area, "cred-form", formData{Cred: c, Rotate: true, Error: err.Error()})
		return
	}
	h.d.ReloadModels(r.Context())
	h.d.Audit(r, "rotate", "credential", c.ID, "Rotated secret of credential "+c.Name, before, redacted(c))
	ui.Done(w, "Secret rotated — deployments use it immediately", "refresh-credentials")
}

type usageData struct {
	Cred store.Credential
	Refs []store.CredentialRef
}

func (h *H) usage(w http.ResponseWriter, r *http.Request) {
	c, ok := h.load(w, r)
	if !ok {
		return
	}
	refs, _ := h.d.Store.CredentialUsage(r.Context(), c.ID)
	h.d.Partial(w, r, 200, area, "cred-usage", usageData{Cred: c, Refs: refs})
}

func (h *H) delete(w http.ResponseWriter, r *http.Request) {
	c, ok := h.load(w, r)
	if !ok {
		return
	}
	refs, _ := h.d.Store.CredentialUsage(r.Context(), c.ID)
	if len(refs) > 0 {
		// Explain where it is used instead of deleting (rendered into the modal).
		ui.Toast(w, "warning", c.Name+" is still in use and was not deleted")
		h.d.Partial(w, r, 200, area, "cred-usage", usageData{Cred: c, Refs: refs})
		return
	}
	if err := h.d.Store.DeleteCredential(r.Context(), c.ID); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.ReloadModels(r.Context())
	h.d.Audit(r, "delete", "credential", c.ID, "Deleted credential "+c.Name, redacted(c), nil)
	ui.Done(w, "Credential deleted", "refresh-credentials")
}
