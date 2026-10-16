// Package sso implements OpenID Connect single sign-on for the console:
// authorization-code flow with PKCE, ID-token verification, role mapping from a
// claim, account linking/auto-provisioning and default team assignment.
package sso

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"golang.org/x/oauth2"

	"lemongate/internal/auth"
	"lemongate/internal/config"
	"lemongate/internal/store"
	"lemongate/internal/ui"
	"lemongate/internal/ui/session"
)

const (
	stateCookie = "lg_sso"
	stateTTL    = 10 * time.Minute
	cookiePath  = "/ui/sso"
)

type H struct {
	d   *ui.Deps
	cfg config.OIDCConfig

	mu       sync.Mutex
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
	client   *http.Client
}

// Mount registers public SSO routes (/ui/sso/login, /ui/sso/callback) when OIDC is
// configured. Returns whether SSO is enabled.
func Mount(r chi.Router, d *ui.Deps) bool {
	if d.Cfg == nil || !d.Cfg.OIDC.Enabled() {
		return false
	}
	h := &H{d: d, cfg: d.Cfg.OIDC, client: &http.Client{Timeout: 15 * time.Second}}
	r.Get("/ui/sso/login", h.login)
	r.Get("/ui/sso/callback", h.callback)
	return true
}

// init discovers the provider lazily so startup never depends on the IdP being up.
func (h *H) init() (*oidc.Provider, *oidc.IDTokenVerifier, *oauth2.Config, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.provider != nil {
		return h.provider, h.verifier, h.oauth, nil
	}
	// Background context: go-oidc keeps it for later JWKS refreshes.
	ctx := oidc.ClientContext(context.Background(), h.client)
	p, err := oidc.NewProvider(ctx, h.cfg.Issuer)
	if err != nil {
		return nil, nil, nil, err
	}
	scopes := h.cfg.Scopes
	if !slices.Contains(scopes, oidc.ScopeOpenID) {
		scopes = append([]string{oidc.ScopeOpenID}, scopes...)
	}
	h.provider = p
	h.verifier = p.Verifier(&oidc.Config{ClientID: h.cfg.ClientID})
	h.oauth = &oauth2.Config{ClientID: h.cfg.ClientID, ClientSecret: h.cfg.ClientSecret, Endpoint: p.Endpoint(),
		RedirectURL: strings.TrimRight(h.d.Cfg.BaseURL, "/") + "/ui/sso/callback", Scopes: scopes}
	return h.provider, h.verifier, h.oauth, nil
}

// flowState travels in an encrypted, HttpOnly cookie between login and callback.
type flowState struct {
	State    string    `json:"s"`
	Nonce    string    `json:"n"`
	Verifier string    `json:"v"`
	Next     string    `json:"x"`
	Expires  time.Time `json:"e"`
}

func (h *H) sealState(fs flowState) (string, error) {
	b, _ := json.Marshal(fs)
	sealed, err := h.d.Box.Seal(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (h *H) openState(v string) (flowState, error) {
	var fs flowState
	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return fs, err
	}
	plain, err := h.d.Box.Open(raw)
	if err != nil {
		return fs, err
	}
	if err := json.Unmarshal(plain, &fs); err != nil {
		return fs, err
	}
	if time.Now().After(fs.Expires) {
		return fs, errors.New("sign-in attempt expired")
	}
	return fs, nil
}

func (h *H) secure() bool { return strings.HasPrefix(h.d.Cfg.BaseURL, "https://") }

func (h *H) login(w http.ResponseWriter, r *http.Request) {
	_, _, oc, err := h.init()
	if err != nil {
		slog.Error("oidc discovery failed", "issuer", h.cfg.Issuer, "err", err)
		h.fail(w, http.StatusBadGateway, "The identity provider is unreachable",
			"LemonGate could not load the identity provider's configuration. Try again in a moment, or sign in with your email and password.", err)
		return
	}
	fs := flowState{State: auth.RandomString(32), Nonce: auth.RandomString(32), Verifier: oauth2.GenerateVerifier(),
		Next: SafeNext(r.URL.Query().Get("next")), Expires: time.Now().Add(stateTTL)}
	v, err := h.sealState(fs)
	if err != nil {
		h.fail(w, 500, "Could not start single sign-on", "An internal error occurred.", err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: v, Path: cookiePath, HttpOnly: true, Secure: h.secure(),
		SameSite: http.SameSiteLaxMode, MaxAge: int(stateTTL.Seconds())})
	http.Redirect(w, r, oc.AuthCodeURL(fs.State, oidc.Nonce(fs.Nonce), oauth2.S256ChallengeOption(fs.Verifier)), http.StatusFound)
}

func (h *H) clearState(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: "", Path: cookiePath, MaxAge: -1, HttpOnly: true, Secure: h.secure(),
		SameSite: http.SameSiteLaxMode})
}

func (h *H) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	h.clearState(w)
	if e := q.Get("error"); e != "" {
		desc := q.Get("error_description")
		if desc == "" {
			desc = e
		}
		h.fail(w, http.StatusUnauthorized, "Sign-in was not completed", "The identity provider returned: "+desc, nil)
		return
	}
	c, err := r.Cookie(stateCookie)
	if err != nil {
		h.fail(w, http.StatusBadRequest, "Sign-in session expired", "Start again from the sign-in page. Make sure cookies are enabled.", nil)
		return
	}
	fs, err := h.openState(c.Value)
	if err != nil || subtle.ConstantTimeCompare([]byte(fs.State), []byte(q.Get("state"))) != 1 {
		h.fail(w, http.StatusBadRequest, "Sign-in session expired", "The sign-in attempt is invalid or too old. Start again from the sign-in page.", err)
		return
	}
	p, verifier, oc, err := h.init()
	if err != nil {
		h.fail(w, http.StatusBadGateway, "The identity provider is unreachable", "Try again in a moment.", err)
		return
	}
	ctx, cancel := context.WithTimeout(oidc.ClientContext(r.Context(), h.client), 20*time.Second)
	defer cancel()
	tok, err := oc.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(fs.Verifier))
	if err != nil {
		h.fail(w, http.StatusBadGateway, "Could not complete sign-in", "The authorization code could not be exchanged with the identity provider.", err)
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		h.fail(w, http.StatusBadGateway, "Could not complete sign-in", "The identity provider did not return an ID token.", nil)
		return
	}
	idt, err := verifier.Verify(ctx, rawID)
	if err != nil {
		h.fail(w, http.StatusUnauthorized, "Could not verify your identity", "The ID token failed verification.", err)
		return
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(fs.Nonce)) != 1 {
		h.fail(w, http.StatusUnauthorized, "Could not verify your identity", "The ID token nonce does not match this sign-in attempt.", nil)
		return
	}
	claims := map[string]any{}
	if err := idt.Claims(&claims); err != nil {
		h.fail(w, http.StatusBadGateway, "Could not read your profile", "The ID token claims are malformed.", err)
		return
	}
	// Fill gaps (email, name, groups) from the userinfo endpoint when available.
	if p.UserInfoEndpoint() != "" {
		if info, err := p.UserInfo(ctx, oauth2.StaticTokenSource(tok)); err == nil {
			extra := map[string]any{}
			if info.Claims(&extra) == nil {
				MergeClaims(claims, extra)
			}
		}
	}
	id, err := ExtractIdentity(claims)
	if err != nil {
		h.fail(w, http.StatusForbidden, "Your account can't be used here", err.Error(), nil)
		return
	}
	role, hasRole := MapRole(claims, h.cfg.RoleClaim, h.cfg.AdminValues, h.cfg.DefaultRole)
	u, err := h.resolveUser(r.Context(), id, role, hasRole)
	if err != nil {
		var ue userError
		if errors.As(err, &ue) {
			h.fail(w, http.StatusForbidden, ue.title, ue.msg, nil)
			return
		}
		h.fail(w, 500, "Could not sign you in", "An internal error occurred while loading your account.", err)
		return
	}
	_ = h.d.Store.TouchUserLogin(r.Context(), u.ID)
	if err := session.StartSession(w, r, h.d, &u.ID, false); err != nil {
		h.fail(w, 500, "Could not start a session", "An internal error occurred.", err)
		return
	}
	slog.Info("sso sign-in", "email", u.Email, "role", u.Role)
	http.Redirect(w, r, SafeNext(fs.Next), http.StatusSeeOther)
}

type userError struct{ title, msg string }

func (e userError) Error() string { return e.msg }

// resolveUser finds the user by SSO subject, then by email (linking the subject),
// or provisions a new one. The role is updated only when the role claim is present.
func (h *H) resolveUser(ctx context.Context, id Identity, role string, hasRole bool) (store.User, error) {
	u, err := h.d.Store.GetUserBySSO(ctx, id.Subject)
	isNew := false
	switch {
	case err == nil:
	case errors.Is(err, store.ErrNotFound):
		u, err = h.d.Store.GetUserByEmail(ctx, id.Email)
		switch {
		case err == nil:
			if u.SSOSubject != nil && *u.SSOSubject != "" && *u.SSOSubject != id.Subject {
				return u, userError{"Account already linked", "This email is linked to a different single sign-on identity. Ask an administrator to unlink it."}
			}
			// Linking by email hands the existing account (possibly an admin) to whoever
			// controls that address at the provider, so it must be verified.
			if !id.EmailVerified && !h.cfg.TrustEmail {
				return u, userError{"Email not verified", "An account with this email already exists, but your identity provider did not confirm that the address is verified, so it can't be linked automatically. Ask an administrator."}
			}
			if err := h.d.Store.LinkUserSSO(ctx, u.ID, id.Subject); err != nil {
				return u, err
			}
			h.d.Store.Audit(ctx, u.ID, "sso", "link_sso", "user", u.ID, "Linked single sign-on identity for "+u.Email, nil, nil)
			isNew = true
		case errors.Is(err, store.ErrNotFound):
			sub := id.Subject
			u, err = h.d.Store.CreateUser(ctx, store.User{Email: id.Email, Name: id.Name, Role: role, SSOSubject: &sub})
			if err != nil {
				return u, err
			}
			h.d.Store.Audit(ctx, u.ID, "sso", "create", "user", u.ID, "Provisioned "+u.Email+" via single sign-on", nil,
				map[string]any{"email": u.Email, "role": u.Role})
			isNew, hasRole = true, false // role already applied
			h.d.Changed()
		default:
			return u, err
		}
	default:
		return u, err
	}
	if u.Blocked {
		return u, userError{"Account disabled", "This account has been disabled. Contact an administrator."}
	}
	if hasRole && u.Role != role {
		before := u.Role
		u.Role = role
		if err := h.d.Store.UpdateUser(ctx, u); err != nil {
			return u, err
		}
		h.d.Store.Audit(ctx, u.ID, "sso", "update", "user", u.ID, fmt.Sprintf("Role for %s set to %s from SSO claim", u.Email, role),
			map[string]any{"role": before}, map[string]any{"role": role})
		h.d.Changed()
	}
	if isNew && h.cfg.DefaultTeam != "" {
		if t, err := h.d.Store.GetTeamByName(ctx, h.cfg.DefaultTeam); err == nil {
			if _, err := h.d.Store.GetMembership(ctx, t.ID, u.ID); errors.Is(err, store.ErrNotFound) {
				if err := h.d.Store.UpsertTeamMember(ctx, t.ID, u.ID, auth.TeamRoleMember, nil); err == nil {
					h.d.Store.Audit(ctx, u.ID, "sso", "add_member", "team", t.ID, "Added "+u.Email+" to default team "+t.Name, nil, nil)
					h.d.Changed()
				}
			}
		} else {
			slog.Warn("sso default team not found", "team", h.cfg.DefaultTeam)
		}
	}
	return u, nil
}

type errorData struct {
	Heading string
	Message string
	Detail  string
}

func (h *H) fail(w http.ResponseWriter, status int, heading, msg string, err error) {
	data := errorData{Heading: heading, Message: msg}
	if err != nil {
		slog.Warn("sso failure", "heading", heading, "err", err)
		if h.d.Cfg.DevMode {
			data.Detail = err.Error()
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	h.d.R.Exec(w, status, "sso/error", "auth", ui.Page{Title: "Single sign-on", Brand: h.d.Settings.Current().Branding,
		Data: data, Version: h.d.R.Version, Features: h.d.Features})
}

// SafeNext keeps redirects inside the console.
func SafeNext(next string) string { return ui.SafeNext(next) }

// --- claims ---

// Identity is the subset of claims LemonGate needs.
type Identity struct {
	Subject string
	Email   string
	Name    string
	// EmailVerified is true only when the email claim itself was present and the
	// provider asserted email_verified. Fallback usernames are never verified.
	EmailVerified bool
}

// ExtractIdentity reads sub/email/name, falling back to common alternatives.
func ExtractIdentity(c map[string]any) (Identity, error) {
	id := Identity{Subject: str(c["sub"]), Email: strings.ToLower(strings.TrimSpace(str(c["email"])))}
	if id.Subject == "" {
		return id, errors.New("the identity provider did not return a subject (sub) claim")
	}
	// Some providers send email_verified as a string in userinfo.
	verified := c["email_verified"] == true || strings.EqualFold(str(c["email_verified"]), "true")
	if c["email_verified"] == false || strings.EqualFold(str(c["email_verified"]), "false") {
		return id, errors.New("your email address is not verified with the identity provider")
	}
	id.EmailVerified = id.Email != "" && verified
	if id.Email == "" {
		for _, k := range []string{"preferred_username", "upn", "unique_name"} {
			if v := strings.ToLower(str(c[k])); strings.Contains(v, "@") {
				id.Email = v
				break
			}
		}
	}
	if id.Email == "" {
		return id, errors.New("your identity provider did not share an email address. Ask an administrator to add the \"email\" scope.")
	}
	id.Name = str(c["name"])
	if id.Name == "" {
		id.Name = strings.TrimSpace(str(c["given_name"]) + " " + str(c["family_name"]))
	}
	return id, nil
}

// MapRole maps the role claim to an application role. The claim may be a string
// or an array and may be a dotted path into nested objects (e.g.
// "realm_access.roles"). present reports whether the claim exists at all; when it
// does not, the caller should keep the user's current role.
func MapRole(c map[string]any, claim string, adminValues []string, defaultRole string) (role string, present bool) {
	if !slices.Contains(auth.Roles, defaultRole) {
		defaultRole = auth.RoleMember
	}
	values, present := ClaimValues(c, claim)
	for _, v := range values {
		for _, a := range adminValues {
			if strings.EqualFold(strings.TrimSpace(v), strings.TrimSpace(a)) {
				return auth.RoleAdmin, present
			}
		}
	}
	return defaultRole, present
}

// ClaimValues returns the string values of a (possibly nested) claim.
func ClaimValues(c map[string]any, claim string) ([]string, bool) {
	if claim == "" {
		return nil, false
	}
	v, ok := lookup(c, claim)
	if !ok || v == nil {
		return nil, false
	}
	switch t := v.(type) {
	case string:
		return []string{t}, true
	case []string:
		return t, true
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s := str(x); s != "" {
				out = append(out, s)
			}
		}
		return out, true
	case bool, float64:
		return []string{str(t)}, true
	}
	return nil, true
}

func lookup(c map[string]any, path string) (any, bool) {
	if v, ok := c[path]; ok { // exact key first (claims may contain dots, e.g. URLs)
		return v, true
	}
	cur := any(c)
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[part]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// MergeClaims copies keys from extra that are missing in dst.
func MergeClaims(dst, extra map[string]any) {
	for k, v := range extra {
		if _, ok := dst[k]; !ok {
			dst[k] = v
		}
	}
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	case float64:
		return strings.TrimSuffix(strings.TrimRight(fmt.Sprintf("%f", t), "0"), ".")
	}
	return fmt.Sprint(v)
}
