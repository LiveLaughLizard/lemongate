package ui

import (
	"net/http"
	"net/url"

	"lemongate/internal/auth"
)

const SessionCookie = "lg_session"

// RequireSession loads the browser session or redirects to the login page.
func (d *Deps) RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(SessionCookie)
		var p *auth.Principal
		if err == nil {
			p, err = d.Resolver.ResolveSession(r.Context(), c.Value)
		}
		if err != nil || p == nil {
			to := "/ui/login"
			if r.Method == http.MethodGet && r.URL.Path != "/ui" && r.URL.Path != "/ui/" {
				to += "?next=" + url.QueryEscape(r.URL.RequestURI())
			}
			Redirect(w, r, to)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			tok := r.Header.Get("X-CSRF-Token")
			if tok == "" {
				tok = r.FormValue("csrf")
			}
			if !auth.ConstantTimeEqual(tok, p.SessionCSRF) {
				Fail(w, http.StatusForbidden, "Your session token is stale. Reload the page and try again.")
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), p)))
	})
}

// RequireViewer allows admins and read-only admins.
func RequireViewer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !auth.FromContext(r.Context()).CanViewAll() {
			Forbidden(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireAdmin allows full admins only.
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !auth.FromContext(r.Context()).IsAdmin() {
			Forbidden(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// AdminWrites lets viewers through on GET but requires admin for mutations.
func AdminWrites(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := auth.FromContext(r.Context())
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			if !p.CanViewAll() {
				Forbidden(w, r)
				return
			}
		} else if !p.IsAdmin() {
			Forbidden(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func Forbidden(w http.ResponseWriter, r *http.Request) {
	if IsHTMX(r) {
		Fail(w, http.StatusForbidden, "You don't have permission to do that.")
		return
	}
	http.Error(w, "forbidden", http.StatusForbidden)
}
