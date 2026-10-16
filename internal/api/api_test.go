package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"lemongate/internal/alerting"
	"lemongate/internal/auth"
	"lemongate/internal/settings"
	"lemongate/internal/store"
)

func ptr[T any](v T) *T { return &v }

func keyPrincipal(scope, role string, userID string) *auth.Principal {
	k := &store.Key{ID: "k1", Scope: scope}
	p := &auth.Principal{Kind: "key", Key: k, Role: role}
	if userID != "" {
		k.UserID = ptr(userID)
		p.User = &store.User{ID: userID, Email: userID + "@example.com", Role: role}
	}
	return p
}

func TestScopeCheck(t *testing.T) {
	cases := []struct {
		name   string
		p      *auth.Principal
		status int
	}{
		{"nil", nil, http.StatusUnauthorized},
		{"master", &auth.Principal{Kind: "master", Role: auth.RoleAdmin}, 0},
		{"admin key", keyPrincipal("admin", auth.RoleAdmin, ""), 0},
		{"management key", keyPrincipal("management", auth.RoleMember, "u1"), 0},
		{"management key without owner", keyPrincipal("management", auth.RoleMember, ""), http.StatusForbidden},
		{"inference key", keyPrincipal("inference", auth.RoleMember, "u1"), http.StatusForbidden},
		{"inference key of admin", keyPrincipal("inference", auth.RoleMember, "admin1"), http.StatusForbidden},
		{"session principal", &auth.Principal{Kind: "session", Role: auth.RoleAdmin}, http.StatusForbidden},
	}
	for _, c := range cases {
		if got, _ := scopeCheck(c.p); got != c.status {
			t.Errorf("%s: status %d, want %d", c.name, got, c.status)
		}
	}
}

func TestAllowed(t *testing.T) {
	admin := &auth.Principal{Kind: "master", Role: auth.RoleAdmin}
	viewer := keyPrincipal("management", auth.RoleAdminViewer, "v1")
	member := keyPrincipal("management", auth.RoleMember, "m1")
	memberRO := keyPrincipal("management", auth.RoleMemberViewer, "m2")
	cases := []struct {
		p      *auth.Principal
		level  string
		method string
		want   bool
	}{
		{admin, accessAdmin, "DELETE", true},
		{admin, accessViewer, "POST", true},
		{viewer, accessViewer, "GET", true},
		{viewer, accessViewer, "POST", false},
		{viewer, accessSelf, "POST", false}, // read-only role
		{member, accessViewer, "GET", false},
		{member, accessSelf, "GET", true},
		{member, accessSelf, "POST", true},
		{member, accessAdmin, "GET", false},
		{memberRO, accessSelf, "GET", true},
		{memberRO, accessSelf, "PATCH", false},
	}
	for i, c := range cases {
		if got, _ := allowed(c.p, c.level, c.method); got != c.want {
			t.Errorf("case %d (%s %s %s): got %v want %v", i, c.p.Role, c.level, c.method, got, c.want)
		}
	}
}

func TestApplyKeyMemberRules(t *testing.T) {
	member := keyPrincipal("management", auth.RoleMember, "m1")
	member.Memberships = []store.TeamMember{{TeamID: "t-admin", Role: auth.TeamRoleAdmin}, {TeamID: "t-member", Role: auth.TeamRoleMember}}

	k := store.Key{}
	if msg := applyKey(member, &k, nil, nil); msg != "" || store.Deref(k.UserID) != "m1" || k.Scope != "inference" {
		t.Fatalf("default create: msg=%q user=%v scope=%q", msg, k.UserID, k.Scope)
	}
	k = store.Key{Scope: "admin"}
	if msg := applyKey(member, &k, nil, nil); msg == "" {
		t.Error("member must not create admin-scope keys")
	}
	k = store.Key{UserID: ptr("someone-else")}
	if msg := applyKey(member, &k, nil, nil); msg == "" {
		t.Error("member must not create keys for other users")
	}
	k = store.Key{TeamID: ptr("t-member")}
	if msg := applyKey(member, &k, nil, nil); msg == "" {
		t.Error("member must not create keys for teams they do not administer")
	}
	k = store.Key{TeamID: ptr("t-admin")}
	if msg := applyKey(member, &k, nil, nil); msg != "" {
		t.Errorf("team admin create: %s", msg)
	}
	before := store.Key{UserID: ptr("m1"), Scope: "inference"}
	k = before
	k.Scope = "management"
	if msg := applyKey(member, &k, &before, nil); msg == "" {
		t.Error("member must not change scope")
	}
	k = before
	if msg := applyKey(member, &k, &before, ptr("bogus")); msg == "" {
		t.Error("invalid expires_in accepted")
	}
	k = before
	if msg := applyKey(member, &k, &before, ptr("7d")); msg != "" || k.ExpiresAt == nil || time.Until(*k.ExpiresAt) < 6*24*time.Hour {
		t.Errorf("expires_in 7d: msg=%q exp=%v", msg, k.ExpiresAt)
	}
	admin := &auth.Principal{Kind: "master", Role: auth.RoleAdmin}
	k = store.Key{Scope: "admin"}
	if msg := applyKey(admin, &k, nil, nil); msg != "" {
		t.Errorf("admin create admin key: %s", msg)
	}
	k = store.Key{BudgetPeriod: "fortnightly"}
	if msg := applyKey(admin, &k, nil, nil); msg == "" {
		t.Error("invalid budget period accepted")
	}
}

func TestMergeSettings(t *testing.T) {
	cur := settings.Defaults()
	next, err := mergeSettings(cur, map[string]json.RawMessage{"routing": json.RawMessage(`{"num_retries": 5}`)})
	if err != nil {
		t.Fatal(err)
	}
	if next.Routing.NumRetries != 5 || next.Routing.Strategy != cur.Routing.Strategy || next.Logging != cur.Logging {
		t.Errorf("merge changed the wrong fields: %+v", next.Routing)
	}
	if _, err := mergeSettings(cur, map[string]json.RawMessage{"nope": json.RawMessage(`{}`)}); err == nil {
		t.Error("unknown section accepted")
	}
	if _, err := mergeSettings(cur, map[string]json.RawMessage{"routing": json.RawMessage(`{"bogus": 1}`)}); err == nil {
		t.Error("unknown field accepted")
	}
	if _, err := mergeSettings(cur, map[string]json.RawMessage{"routing": json.RawMessage(`{"num_retries": "x"}`)}); err == nil {
		t.Error("wrong type accepted")
	}
}

func TestCursorRoundTrip(t *testing.T) {
	ts := time.Date(2026, 3, 4, 5, 6, 7, 123456000, time.UTC)
	c := encodeCursor(ts, "abc")
	got, id, ok := decodeCursor(c)
	if !ok || !got.Equal(ts) || id != "abc" {
		t.Fatalf("round trip: %v %v %q", ok, got, id)
	}
	if _, _, ok := decodeCursor("!!"); ok {
		t.Error("garbage cursor accepted")
	}
}

func TestRawBind(t *testing.T) {
	g := &rawTables[0]
	if _, _, err := g.bind(map[string]json.RawMessage{"name": json.RawMessage(`"x"`)}, true); err == nil {
		t.Error("missing required kind accepted")
	}
	if _, _, err := g.bind(map[string]json.RawMessage{"name": json.RawMessage(`"x"`), "kind": json.RawMessage(`"nope"`)}, true); err == nil {
		t.Error("invalid enum accepted")
	}
	if _, _, err := g.bind(map[string]json.RawMessage{"evil; DROP": json.RawMessage(`1`)}, false); err == nil {
		t.Error("unknown column accepted")
	}
	names, args, err := g.bind(map[string]json.RawMessage{"name": json.RawMessage(`"x"`), "kind": json.RawMessage(`"pii"`), "enabled": json.RawMessage(`false`)}, true)
	if err != nil || len(names) != 3 || args[2] != false {
		t.Errorf("bind: %v %v %v", names, args, err)
	}
}

func TestOpenAPIDocument(t *testing.T) {
	h := &H{}
	table := h.routes()
	doc := buildOpenAPI(table, "http://localhost:4000")
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		OpenAPI    string                    `json:"openapi"`
		Paths      map[string]map[string]any `json:"paths"`
		Components struct {
			Schemas map[string]any `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.OpenAPI != "3.1.0" {
		t.Errorf("openapi = %q", parsed.OpenAPI)
	}
	ops := 0
	for _, item := range parsed.Paths {
		ops += len(item)
	}
	if ops != len(table) {
		t.Errorf("document has %d operations, table has %d", ops, len(table))
	}
	// Every referenced schema must exist.
	refs := map[string]bool{}
	for _, rt := range table {
		for _, n := range []string{rt.Body, rt.Resp} {
			if n == "" {
				continue
			}
			if len(n) > 5 && n[:5] == "list:" {
				n = n[5:]
			}
			refs[n] = true
		}
	}
	for n := range refs {
		if _, ok := parsed.Components.Schemas[n]; !ok {
			t.Errorf("schema %s referenced but not defined", n)
		}
	}
	key := parsed.Components.Schemas["Key"].(map[string]any)["properties"].(map[string]any)
	if _, ok := key["key_hash"]; ok {
		t.Error("key_hash must not be exposed")
	}
	if _, ok := key["max_budget"]; !ok {
		t.Error("embedded Budget fields missing from Key schema")
	}
	cred := parsed.Components.Schemas["Credential"].(map[string]any)["properties"].(map[string]any)
	if _, ok := cred["secret_enc"]; ok {
		t.Error("credential secret must not be exposed")
	}
}

func TestApplyChannelKeepsSecrets(t *testing.T) {
	c := alerting.Channel{Kind: alerting.KindWebhook, Config: alerting.ChannelConfig{URL: "https://hooks.example.com/secret-path",
		Secret: "s3cret", Headers: map[string]string{"X-Token": "abc", "X-Old": "gone"}}}
	applyChannel(&c, channelInput{MinSeverity: ptr("critical"), Config: &channelConfigInput{URL: ptr(""), Secret: ptr(""),
		Headers: map[string]string{"X-Token": "", "X-New": "v"}}})
	if c.Config.URL != "https://hooks.example.com/secret-path" || c.Config.Secret != "s3cret" || c.MinSeverity != "critical" {
		t.Fatalf("secrets not kept: %+v", c.Config)
	}
	if c.Config.Headers["X-Token"] != "abc" || c.Config.Headers["X-New"] != "v" || c.Config.Headers["X-Old"] != "" {
		t.Fatalf("headers merge: %v", c.Config.Headers)
	}
	applyChannel(&c, channelInput{Config: &channelConfigInput{Secret: ptr("rotated")}})
	if c.Config.Secret != "rotated" {
		t.Fatal("secret not rotated")
	}
	out, _ := json.Marshal(toChannelOut(c))
	for _, leak := range []string{"rotated", "abc", "secret-path"} {
		if strings.Contains(string(out), leak) {
			t.Errorf("channel JSON leaks %q: %s", leak, out)
		}
	}
}
