// Package session serves sign-in, sign-out and invite acceptance.
package session

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"lemongate/internal/auth"
	"lemongate/internal/store"
	"lemongate/internal/ui"
)

type H struct{ d *ui.Deps }

func Mount(r chi.Router, d *ui.Deps) {
	h := &H{d}
	r.Get("/ui/login", h.loginPage)
	r.Post("/ui/login", h.login)
	r.Post("/ui/logout", h.logout)
	r.Get("/ui/invite/{token}", h.invitePage)
	r.Post("/ui/invite/{token}", h.acceptInvite)
}

type loginData struct {
	Error string
	Next  string
	Email string
	Tab   string
}

func (h *H) page(w http.ResponseWriter, status int, title string, data any) {
	set := "auth/login"
	if _, ok := data.(inviteData); ok {
		set = "auth/invite"
	}
	h.d.R.Exec(w, status, set, "auth", ui.Page{Title: title, Brand: h.d.Settings.Current().Branding, Data: data,
		Version: h.d.R.Version, Features: h.d.Features})
}

func safeNext(next string) string { return ui.SafeNext(next) }

func (h *H) loginPage(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(ui.SessionCookie); err == nil {
		if _, err := h.d.Resolver.ResolveSession(r.Context(), c.Value); err == nil {
			http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusSeeOther)
			return
		}
	}
	h.page(w, 200, "Sign in", loginData{Next: r.URL.Query().Get("next"), Tab: "password", Error: loginErrors[r.URL.Query().Get("error")]})
}

// loginErrors maps ?error= codes to fixed messages so links can't put arbitrary text on the page.
var loginErrors = map[string]string{
	"invite": "That invite link is invalid or has expired.",
}

func (h *H) login(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	next := safeNext(r.FormValue("next"))
	data := loginData{Next: next, Email: ui.FormStr(r, "email"), Tab: "password"}
	if crossSite(r, h.d.Cfg.BaseURL) {
		data.Error = "Sign-in requests must come from this site."
		h.page(w, http.StatusForbidden, "Sign in", data)
		return
	}
	mk := ui.FormStr(r, "master_key")
	isMaster := mk != "" || r.FormValue("tab") == "master"
	ipKey, acctKey := "ip:"+clientIP(r), "user:"+strings.ToLower(data.Email)
	if isMaster {
		acctKey = "master"
	}
	if wait := signIn.blocked(map[string]int{ipKey: maxFailsPerIP, acctKey: maxFailsPerAccount}); wait > 0 {
		if isMaster {
			data.Tab = "master"
		}
		data.Error = fmt.Sprintf("Too many failed sign-in attempts. Try again in %d minutes.", int(wait.Minutes())+1)
		h.page(w, http.StatusTooManyRequests, "Sign in", data)
		return
	}
	var userID *string
	master := false
	if isMaster {
		data.Tab = "master"
		if !h.d.Resolver.IsMaster(mk) {
			signIn.failed(ipKey, acctKey)
			data.Error = "That master key is not valid."
			h.page(w, http.StatusUnauthorized, "Sign in", data)
			return
		}
		master = true
	} else {
		u, err := h.d.Store.GetUserByEmail(r.Context(), data.Email)
		if err != nil || u.PasswordHash == "" {
			auth.CheckPassword(dummyHash, r.FormValue("password"))
		}
		if err != nil || !auth.CheckPassword(u.PasswordHash, r.FormValue("password")) {
			signIn.failed(ipKey, acctKey)
			data.Error = "Incorrect email or password."
			h.page(w, http.StatusUnauthorized, "Sign in", data)
			return
		}
		if u.Blocked {
			data.Error = "This account has been disabled."
			h.page(w, http.StatusForbidden, "Sign in", data)
			return
		}
		userID = &u.ID
		_ = h.d.Store.TouchUserLogin(r.Context(), u.ID)
	}
	signIn.succeeded(acctKey)
	if err := StartSession(w, r, h.d, userID, master); err != nil {
		data.Error = "Could not start a session: " + err.Error()
		h.page(w, 500, "Sign in", data)
		return
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// StartSession issues the session cookie (used by password, master-key and SSO sign-in).
func StartSession(w http.ResponseWriter, r *http.Request, d *ui.Deps, userID *string, master bool) error {
	ttl := time.Duration(max(d.Cfg.SessionHours, 1)) * time.Hour
	token, err := d.Resolver.NewSession(r.Context(), userID, master, ttl, clientIP(r), r.UserAgent())
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: ui.SessionCookie, Value: token, Path: "/", HttpOnly: true,
		Secure: secureCookie(d, r), SameSite: http.SameSiteLaxMode, MaxAge: int(ttl.Seconds())})
	return nil
}

// secureCookie marks the session cookie Secure when the public URL is https or the
// request itself arrived over TLS (directly or via a TLS-terminating proxy).
func secureCookie(d *ui.Deps, r *http.Request) bool {
	return strings.HasPrefix(d.Cfg.BaseURL, "https://") || r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

// clientIP returns the caller's address as resolved by the RealIP middleware.
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func (h *H) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(ui.SessionCookie); err == nil {
		_ = h.d.Store.DeleteSession(r.Context(), auth.HashToken(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: ui.SessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	http.Redirect(w, r, "/ui/login", http.StatusSeeOther)
}

type inviteData struct {
	Token string
	User  store.User
	Error string
}

func (h *H) invitePage(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	uid, err := h.d.Store.PeekInvite(r.Context(), auth.HashToken(token))
	if err != nil {
		http.Redirect(w, r, "/ui/login?error=invite", http.StatusSeeOther)
		return
	}
	u, err := h.d.Store.GetUser(r.Context(), uid)
	if err != nil {
		http.Redirect(w, r, "/ui/login", http.StatusSeeOther)
		return
	}
	h.page(w, 200, "Accept invite", inviteData{Token: token, User: u})
}

func (h *H) acceptInvite(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	_ = r.ParseForm()
	pw := r.FormValue("password")
	uid, err := h.d.Store.PeekInvite(r.Context(), auth.HashToken(token))
	if err != nil {
		http.Redirect(w, r, "/ui/login", http.StatusSeeOther)
		return
	}
	u, _ := h.d.Store.GetUser(r.Context(), uid)
	if crossSite(r, h.d.Cfg.BaseURL) {
		h.page(w, http.StatusForbidden, "Accept invite", inviteData{Token: token, User: u, Error: "Requests must come from this site."})
		return
	}
	if len(pw) < 8 || pw != r.FormValue("confirm") {
		h.page(w, 422, "Accept invite", inviteData{Token: token, User: u, Error: "Passwords must match and be at least 8 characters."})
		return
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		h.page(w, 422, "Accept invite", inviteData{Token: token, User: u, Error: "That password can't be used (at most 72 bytes)."})
		return
	}
	if _, err := h.d.Store.ConsumeInvite(r.Context(), auth.HashToken(token)); err != nil {
		http.Redirect(w, r, "/ui/login", http.StatusSeeOther)
		return
	}
	if err := h.d.Store.SetUserPassword(r.Context(), uid, hash); err != nil {
		http.Redirect(w, r, "/ui/login", http.StatusSeeOther)
		return
	}
	// A password reset signs out every existing session of the account.
	_ = h.d.Store.DeleteUserSessions(r.Context(), uid)
	_ = h.d.Store.TouchUserLogin(r.Context(), uid)
	if err := StartSession(w, r, h.d, &uid, false); err != nil {
		http.Redirect(w, r, "/ui/login", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/ui", http.StatusSeeOther)
}
