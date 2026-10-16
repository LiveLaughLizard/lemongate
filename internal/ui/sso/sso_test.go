package sso

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"lemongate/internal/auth"
	"lemongate/internal/config"
	"lemongate/internal/db"
	"lemongate/internal/gateway"
	"lemongate/internal/secret"
	"lemongate/internal/settings"
	"lemongate/internal/store"
	"lemongate/internal/ui"
	"lemongate/web"
)

func TestMapRole(t *testing.T) {
	admins := []string{"lemongate-admins", "Platform"}
	cases := []struct {
		name        string
		claims      map[string]any
		claim       string
		def         string
		wantRole    string
		wantPresent bool
	}{
		{"array with admin", map[string]any{"groups": []any{"eng", "lemongate-admins"}}, "groups", "member", auth.RoleAdmin, true},
		{"array without admin", map[string]any{"groups": []any{"eng"}}, "groups", "member", auth.RoleMember, true},
		{"string admin (case-insensitive)", map[string]any{"role": "platform"}, "role", "member", auth.RoleAdmin, true},
		{"string non-admin", map[string]any{"role": "dev"}, "role", "member_viewer", auth.RoleMemberViewer, true},
		{"missing claim", map[string]any{"email": "a@b.c"}, "groups", "member", auth.RoleMember, false},
		{"empty array present", map[string]any{"groups": []any{}}, "groups", "member", auth.RoleMember, true},
		{"nested path", map[string]any{"realm_access": map[string]any{"roles": []any{"Platform"}}}, "realm_access.roles", "member", auth.RoleAdmin, true},
		{"dotted key literal", map[string]any{"https://example.com/roles": []any{"lemongate-admins"}}, "https://example.com/roles", "member", auth.RoleAdmin, true},
		{"invalid default falls back to member", map[string]any{}, "groups", "superuser", auth.RoleMember, false},
		{"admin_viewer default", map[string]any{"groups": []any{"x"}}, "groups", "admin_viewer", auth.RoleAdminViewer, true},
		{"no claim configured", map[string]any{"groups": []any{"lemongate-admins"}}, "", "member", auth.RoleMember, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			role, present := MapRole(tc.claims, tc.claim, admins, tc.def)
			if role != tc.wantRole || present != tc.wantPresent {
				t.Errorf("MapRole = (%q, %v), want (%q, %v)", role, present, tc.wantRole, tc.wantPresent)
			}
		})
	}
}

func TestExtractIdentity(t *testing.T) {
	id, err := ExtractIdentity(map[string]any{"sub": "abc", "email": "Ada@Example.com", "given_name": "Ada", "family_name": "Lovelace"})
	if err != nil || id.Email != "ada@example.com" || id.Name != "Ada Lovelace" || id.Subject != "abc" {
		t.Fatalf("unexpected %+v %v", id, err)
	}
	id, err = ExtractIdentity(map[string]any{"sub": "abc", "preferred_username": "bob@corp.io", "name": "Bob"})
	if err != nil || id.Email != "bob@corp.io" {
		t.Fatalf("preferred_username fallback failed: %+v %v", id, err)
	}
	if _, err := ExtractIdentity(map[string]any{"sub": "abc", "preferred_username": "bob"}); err == nil {
		t.Error("missing email accepted")
	}
	if _, err := ExtractIdentity(map[string]any{"email": "a@b.c"}); err == nil {
		t.Error("missing sub accepted")
	}
	if _, err := ExtractIdentity(map[string]any{"sub": "x", "email": "a@b.c", "email_verified": false}); err == nil {
		t.Error("unverified email accepted")
	}
	if _, err := ExtractIdentity(map[string]any{"sub": "x", "email": "a@b.c", "email_verified": "false"}); err == nil {
		t.Error("string \"false\" email_verified accepted")
	}
	for _, c := range []struct {
		claims map[string]any
		want   bool
	}{
		{map[string]any{"sub": "x", "email": "a@b.c", "email_verified": true}, true},
		{map[string]any{"sub": "x", "email": "a@b.c", "email_verified": "true"}, true},
		{map[string]any{"sub": "x", "email": "a@b.c"}, false},
		{map[string]any{"sub": "x", "preferred_username": "a@b.c", "email_verified": true}, false},
	} {
		if id, err := ExtractIdentity(c.claims); err != nil || id.EmailVerified != c.want {
			t.Errorf("ExtractIdentity(%v).EmailVerified = %v (err %v), want %v", c.claims, id.EmailVerified, err, c.want)
		}
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{
		"":                  "/ui",
		"/ui/keys?x=1":      "/ui/keys?x=1",
		"https://evil.com":  "/ui",
		"//evil.com/ui":     "/ui",
		"/api/v1/keys":      "/ui",
		"/ui\\@evil.com":    "/ui",
		"/ui/../\\evil.com": "/ui",
		"/ui/../api/v1":     "/ui",
		"/ui/./keys/../x":   "/ui/x",
		"/uix":              "/ui",
		"/ui":               "/ui",
	} {
		if got := SafeNext(in); got != want {
			t.Errorf("SafeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStateRoundTrip(t *testing.T) {
	box, _ := secret.New("k")
	h := &H{d: &ui.Deps{Box: box, Cfg: &config.Config{}}}
	v, err := h.sealState(flowState{State: "s", Nonce: "n", Verifier: "v", Next: "/ui/keys", Expires: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	fs, err := h.openState(v)
	if err != nil || fs.State != "s" || fs.Next != "/ui/keys" {
		t.Fatalf("round trip failed: %+v %v", fs, err)
	}
	if _, err := h.openState(v[:len(v)-2] + "AA"); err == nil {
		t.Error("tampered state accepted")
	}
	expired, _ := h.sealState(flowState{State: "s", Expires: time.Now().Add(-time.Second)})
	if _, err := h.openState(expired); err == nil {
		t.Error("expired state accepted")
	}
}

func TestMountDisabled(t *testing.T) {
	r := chi.NewRouter()
	if Mount(r, &ui.Deps{Cfg: &config.Config{}}) {
		t.Fatal("SSO reported enabled without configuration")
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/ui/sso/login", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when disabled, got %d", rec.Code)
	}
}

func TestLoginProviderDown(t *testing.T) {
	box, _ := secret.New("k")
	d := &ui.Deps{Box: box, Settings: settings.NewStore(nil), R: ui.NewRenderer(web.FS(""), false),
		Cfg: &config.Config{BaseURL: "http://lg.test", OIDC: config.OIDCConfig{Issuer: "http://127.0.0.1:1", ClientID: "c"}}}
	r := chi.NewRouter()
	if !Mount(r, d) {
		t.Fatal("expected enabled")
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/ui/sso/login", nil))
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "identity provider is unreachable") {
		t.Fatalf("expected friendly error page, got %d: %.300s", rec.Code, rec.Body.String())
	}
}

// --- full flow against a fake identity provider (needs a database) ---

type fakeIdP struct {
	srv       *httptest.Server
	key       *rsa.PrivateKey
	claims    map[string]any
	challenge string
	nonce     string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	f := &fakeIdP{key: key}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint": f.srv.URL + "/token", "jwks_uri": f.srv.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		sum := sha256.Sum256([]byte(r.FormValue("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != f.challenge || r.FormValue("code") != "good-code" {
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		}
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
		c := map[string]any{"iss": f.srv.URL, "aud": "client", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": f.nonce}
		for k, v := range f.claims {
			c[k] = v
		}
		raw, _ := jwt.Signed(signer).Claims(c).Serialize()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": raw, "expires_in": 3600})
	})
	t.Cleanup(f.srv.Close)
	return f
}

func TestFullFlow(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	st := store.New(pool)
	box, _ := secret.New("k")
	idp := newFakeIdP(t)
	email := "sso-test-" + auth.RandomString(8) + "@example.com"
	sub := "sub-" + auth.RandomString(12)
	team, err := st.CreateTeam(ctx, store.Team{Name: "sso-default-" + auth.RandomString(6)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE email=$1`, email)
		_, _ = pool.Exec(context.Background(), `DELETE FROM teams WHERE id=$1`, team.ID)
	})
	cfg := &config.Config{BaseURL: "http://lg.test", SessionHours: 1, OIDC: config.OIDCConfig{Issuer: idp.srv.URL, ClientID: "client",
		ClientSecret: "secret", Scopes: []string{"openid", "email"}, RoleClaim: "groups", AdminValues: []string{"admins"},
		DefaultRole: "member", DefaultTeam: team.Name}}
	d := &ui.Deps{Cfg: cfg, Store: st, Box: box, Settings: settings.NewStore(pool), Resolver: auth.NewResolver(st, "mk"),
		Gateway: gateway.New(&gateway.Gateway{}), R: ui.NewRenderer(web.FS(""), false)}
	r := chi.NewRouter()
	Mount(r, d)

	signIn := func(groups []any) *httptest.ResponseRecorder {
		t.Helper()
		claims := map[string]any{"sub": sub, "email": email, "name": "Sso Tester"}
		if groups != nil {
			claims["groups"] = groups
		}
		idp.claims = claims
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest("GET", "/ui/sso/login?next=/ui/keys", nil))
		if rec.Code != http.StatusFound {
			t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
		}
		loc, _ := url.Parse(rec.Header().Get("Location"))
		q := loc.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("redirect_uri") != "http://lg.test/ui/sso/callback" {
			t.Fatalf("bad authorize URL %s", loc)
		}
		idp.challenge, idp.nonce = q.Get("code_challenge"), q.Get("nonce")
		req := httptest.NewRequest("GET", "/ui/sso/callback?code=good-code&state="+url.QueryEscape(q.Get("state")), nil)
		for _, c := range rec.Result().Cookies() {
			req.AddCookie(c)
		}
		out := httptest.NewRecorder()
		r.ServeHTTP(out, req)
		return out
	}

	// First login provisions the user as admin and adds the default team.
	rec := signIn([]any{"eng", "admins"})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/ui/keys" {
		t.Fatalf("callback: %d %s %.500s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	if !strings.Contains(strings.Join(rec.Header().Values("Set-Cookie"), "\n"), ui.SessionCookie+"=") {
		t.Fatal("no session cookie issued")
	}
	u, err := st.GetUserByEmail(ctx, email)
	if err != nil || u.Role != auth.RoleAdmin || u.SSOSubject == nil || *u.SSOSubject != sub {
		t.Fatalf("user not provisioned correctly: %+v %v", u, err)
	}
	if _, err := st.GetMembership(ctx, team.ID, u.ID); err != nil {
		t.Fatalf("default team membership missing: %v", err)
	}
	// Claim present without admin value → demoted to default role.
	if rec := signIn([]any{"eng"}); rec.Code != http.StatusSeeOther {
		t.Fatalf("second login failed: %d", rec.Code)
	}
	if u, _ = st.GetUserByEmail(ctx, email); u.Role != auth.RoleMember {
		t.Fatalf("role not updated from claim: %s", u.Role)
	}
	// Claim absent → role kept.
	u.Role = auth.RoleAdminViewer
	_ = st.UpdateUser(ctx, u)
	if rec := signIn(nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("third login failed: %d", rec.Code)
	}
	if u, _ = st.GetUserByEmail(ctx, email); u.Role != auth.RoleAdminViewer {
		t.Fatalf("role changed without claim: %s", u.Role)
	}
	// Blocked users are refused.
	u.Blocked = true
	_ = st.UpdateUser(ctx, u)
	if rec := signIn(nil); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "disabled") {
		t.Fatalf("blocked user signed in: %d", rec.Code)
	}
	// Tampered state is rejected.
	req := httptest.NewRequest("GET", "/ui/sso/callback?code=good-code&state=nope", nil)
	out := httptest.NewRecorder()
	r.ServeHTTP(out, req)
	if out.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without state cookie, got %d", out.Code)
	}
}
