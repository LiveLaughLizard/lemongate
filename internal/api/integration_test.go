package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"lemongate/internal/alerting"
	"lemongate/internal/auth"
	"lemongate/internal/config"
	"lemongate/internal/db"
	"lemongate/internal/gateway"
	"lemongate/internal/routing"
	"lemongate/internal/secret"
	"lemongate/internal/settings"
	"lemongate/internal/spend"
	"lemongate/internal/store"
	"lemongate/internal/ui"
	"lemongate/web"
)

const testMaster = "lg-test-master-api"

// newTestServer wires the API against a real (already migrated) database.
func newTestServer(t *testing.T) (*httptest.Server, *ui.Deps) {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, url)
	if err != nil {
		t.Skipf("database unavailable: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	box, _ := secret.New("test-secret")
	st := store.New(pool)
	sets := settings.NewStore(pool)
	if err := sets.Load(ctx, nil); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{BaseURL: "http://test", MasterKey: testMaster}
	reg := routing.NewRegistry(st, box, config.FileConfig{}, sets)
	_ = reg.Reload(ctx)
	sw := spend.NewWriter(pool)
	res := auth.NewResolver(st, testMaster)
	gw := gateway.New(&gateway.Gateway{Store: st, Resolver: res, Registry: reg, Spend: sw, Settings: sets})
	al := alerting.New(pool, box, sets, config.SMTPConfig{})
	d := &ui.Deps{Alerter: al, Cfg: cfg, Store: st, Settings: sets, Registry: reg, Resolver: res, Spend: sw, Gateway: gw, Box: box,
		R: ui.NewRenderer(web.FS(""), false)}
	r := chi.NewRouter()
	Mount(r, d)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv, d
}

type client struct {
	t     *testing.T
	base  string
	token string
}

func (c client) do(method, path string, body any) (int, map[string]any) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func (c client) must(method, path string, body any, want int) map[string]any {
	c.t.Helper()
	status, out := c.do(method, path, body)
	if status != want {
		c.t.Fatalf("%s %s: status %d, want %d: %v", method, path, status, want, out)
	}
	return out
}

func TestIntegration(t *testing.T) {
	srv, d := newTestServer(t)
	ctx := context.Background()
	sfx := fmt.Sprint(time.Now().UnixNano())
	master := client{t, srv.URL, testMaster}

	// --- authentication ---
	if st, out := (client{t, srv.URL, ""}).do("GET", "/api/v1/me", nil); st != 401 || out["error"] == nil {
		t.Fatalf("no token: %d %v", st, out)
	}
	if st, _ := (client{t, srv.URL, "lg-bogus"}).do("GET", "/api/v1/me", nil); st != 401 {
		t.Fatalf("bogus token: %d", st)
	}
	me := master.must("GET", "/api/v1/me", nil, 200)
	if me["role"] != "admin" {
		t.Fatalf("master role: %v", me)
	}

	// --- users & keys ---
	u := master.must("POST", "/api/v1/users", map[string]any{"email": "api-" + sfx + "@example.com", "role": "member"}, 201)
	uid := u["id"].(string)
	t.Cleanup(func() { _ = d.Store.DeleteUser(ctx, uid) })
	master.must("POST", "/api/v1/users", map[string]any{"email": "bad", "role": "member"}, 400)
	master.must("POST", "/api/v1/users", map[string]any{"email": "x" + sfx + "@example.com", "role": "superuser"}, 400)

	mk := master.must("POST", "/api/v1/keys", map[string]any{"alias": "mgmt-" + sfx, "user_id": uid, "scope": "management"}, 201)
	inf := master.must("POST", "/api/v1/keys", map[string]any{"alias": "inf-" + sfx, "user_id": uid}, 201)
	other := master.must("POST", "/api/v1/keys", map[string]any{"alias": "other-" + sfx}, 201)
	for _, k := range []map[string]any{mk, inf, other} {
		id := k["id"].(string)
		t.Cleanup(func() { _ = d.Store.PurgeKey(ctx, id) })
		if !strings.HasPrefix(k["key"].(string), "lg-") {
			t.Fatalf("plaintext key missing: %v", k)
		}
	}
	if st, out := (client{t, srv.URL, inf["key"].(string)}).do("GET", "/api/v1/me", nil); st != 403 {
		t.Fatalf("inference key: %d %v", st, out)
	}

	member := client{t, srv.URL, mk["key"].(string)}
	member.must("GET", "/api/v1/users", nil, 403)
	member.must("GET", "/api/v1/settings", nil, 403)
	member.must("POST", "/api/v1/deployments", map[string]any{"name": "x"}, 403)
	own := member.must("POST", "/api/v1/keys", map[string]any{"alias": "own-" + sfx}, 201)
	t.Cleanup(func() { _ = d.Store.PurgeKey(ctx, own["id"].(string)) })
	if own["user_id"] != uid || own["scope"] != "inference" {
		t.Fatalf("member key ownership: %v", own)
	}
	member.must("POST", "/api/v1/keys", map[string]any{"alias": "x", "scope": "admin"}, 400)
	list := member.must("GET", "/api/v1/keys", nil, 200)
	for _, it := range list["data"].([]any) {
		if it.(map[string]any)["user_id"] != uid {
			t.Fatalf("member sees foreign key: %v", it)
		}
	}
	member.must("GET", "/api/v1/keys/"+other["id"].(string), nil, 404)
	member.must("PATCH", "/api/v1/keys/"+other["id"].(string), map[string]any{"alias": "pwn"}, 404)
	member.must("PATCH", "/api/v1/keys/"+own["id"].(string), map[string]any{"rpm_limit": 7}, 200)
	member.must("POST", "/api/v1/keys/"+own["id"].(string)+"/block", nil, 200)
	regen := member.must("POST", "/api/v1/keys/"+own["id"].(string)+"/regenerate", nil, 200)
	if regen["key"] == own["key"] || regen["blocked"] != true || regen["rpm_limit"].(float64) != 7 {
		t.Fatalf("regenerate: %v", regen)
	}
	member.must("GET", "/api/v1/usage?group_by=key", nil, 200)
	logs := member.must("GET", "/api/v1/logs?limit=5", nil, 200)
	if _, ok := logs["data"]; !ok {
		t.Fatalf("logs: %v", logs)
	}
	member.must("DELETE", "/api/v1/keys/"+own["id"].(string), nil, 200)

	// --- teams & members ---
	team := master.must("POST", "/api/v1/teams", map[string]any{"name": "api-team-" + sfx, "max_budget": 10, "budget_period": "monthly"}, 201)
	tid := team["id"].(string)
	t.Cleanup(func() { _, _ = d.Store.Pool.Exec(ctx, `DELETE FROM teams WHERE id=$1`, tid) })
	member.must("GET", "/api/v1/teams/"+tid, nil, 404)
	master.must("POST", "/api/v1/teams/"+tid+"/members", map[string]any{"user_id": uid, "role": "team_member"}, 200)
	d.Resolver.Invalidate()
	member.must("GET", "/api/v1/teams/"+tid, nil, 200)
	member.must("POST", "/api/v1/teams/"+tid+"/members", map[string]any{"user_id": uid, "role": "team_admin"}, 403)
	patched := master.must("PATCH", "/api/v1/teams/"+tid, map[string]any{"rpm_limit": 9}, 200)
	if patched["max_budget"].(float64) != 10 || patched["rpm_limit"].(float64) != 9 {
		t.Fatalf("partial team update lost fields: %v", patched)
	}
	master.must("DELETE", "/api/v1/teams/"+tid+"/members/"+uid, nil, 200)

	// --- credentials & deployments ---
	cred := master.must("POST", "/api/v1/credentials", map[string]any{"name": "api-cred-" + sfx, "secret": "supersecretvalue"}, 201)
	cid := cred["id"].(string)
	if _, ok := cred["secret_enc"]; ok || cred["hint"] == "" {
		t.Fatalf("credential leaked or missing hint: %v", cred)
	}
	dep := master.must("POST", "/api/v1/deployments", map[string]any{"name": "api-model-" + sfx, "api_base": "http://localhost:9/v1",
		"upstream_model": "m", "credential_id": cid}, 201)
	if dep["enabled"] != true || dep["weight"].(float64) != 1 {
		t.Fatalf("deployment defaults: %v", dep)
	}
	master.must("POST", "/api/v1/deployments", map[string]any{"name": "x", "api_base": "ftp://x", "upstream_model": "m"}, 400)
	master.must("PATCH", "/api/v1/deployments/"+dep["id"].(string), map[string]any{"weight": 4}, 200)
	master.must("DELETE", "/api/v1/deployments/"+dep["id"].(string), nil, 200)
	master.must("DELETE", "/api/v1/credentials/"+cid, nil, 200)
	health := master.must("GET", "/api/v1/health", nil, 200)
	if _, ok := health["deployments"]; !ok {
		t.Fatalf("health: %v", health)
	}

	// --- raw tables ---
	g := master.must("POST", "/api/v1/guardrails", map[string]any{"name": "api-g-" + sfx, "kind": "blocklist", "config": map[string]any{"words": []string{"x"}}}, 201)
	master.must("POST", "/api/v1/guardrails", map[string]any{"name": "api-g-" + sfx, "kind": "blocklist"}, 409)
	g2 := master.must("PATCH", "/api/v1/guardrails/"+g["name"].(string), map[string]any{"action": "log"}, 200)
	if g2["action"] != "log" || g2["kind"] != "blocklist" {
		t.Fatalf("guardrail patch: %v", g2)
	}
	master.must("PATCH", "/api/v1/guardrails/"+g["id"].(string), map[string]any{"mode": "sideways"}, 400)
	master.must("DELETE", "/api/v1/guardrails/"+g["id"].(string), nil, 200)
	master.must("POST", "/api/v1/mcp-servers", map[string]any{"name": "x", "url": "http://x", "credential_id": "00000000-0000-0000-0000-000000000000"}, 400)

	// --- settings ---
	cur := master.must("GET", "/api/v1/settings", nil, 200)
	retries := cur["routing"].(map[string]any)["num_retries"]
	upd := master.must("PATCH", "/api/v1/settings", map[string]any{"routing": map[string]any{"num_retries": 4}}, 200)
	if upd["routing"].(map[string]any)["num_retries"].(float64) != 4 {
		t.Fatalf("settings patch: %v", upd)
	}
	master.must("PATCH", "/api/v1/settings", map[string]any{"routing": map[string]any{"num_retries": retries}}, 200)
	master.must("PATCH", "/api/v1/settings", map[string]any{"routing": map[string]any{"nope": 1}}, 400)

	// --- tags, end users, presets, aliases ---
	master.must("POST", "/api/v1/tags", map[string]any{"name": "api-tag-" + sfx}, 201)
	master.must("POST", "/api/v1/tags", map[string]any{"name": "api-tag-" + sfx}, 409)
	master.must("DELETE", "/api/v1/tags/api-tag-"+sfx, nil, 200)
	p := master.must("POST", "/api/v1/budget-presets", map[string]any{"name": "api-p-" + sfx, "max_budget": 3}, 201)
	master.must("DELETE", "/api/v1/budget-presets/"+p["id"].(string), nil, 200)
	master.must("POST", "/api/v1/aliases", map[string]any{"alias": "api-a-" + sfx, "target": "x"}, 200)
	master.must("DELETE", "/api/v1/aliases/api-a-"+sfx, nil, 200)

	// --- alert channels ---
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer hook.Close()
	ch := master.must("POST", "/api/v1/alert-channels", map[string]any{"name": "api-ch-" + sfx, "kind": "webhook",
		"config": map[string]any{"url": hook.URL + "/secret-path", "secret": "sig", "headers": map[string]string{"X-T": "tok"}}}, 201)
	chID := ch["id"].(string)
	t.Cleanup(func() { _ = d.Alerter.(*alerting.Alerter).DeleteChannel(ctx, chID) })
	if b, _ := json.Marshal(ch); strings.Contains(string(b), "secret-path") || strings.Contains(string(b), "tok") {
		t.Fatalf("channel leaks secrets: %s", b)
	}
	master.must("POST", "/api/v1/alert-channels", map[string]any{"name": "api-ch-" + sfx, "kind": "webhook", "config": map[string]any{"url": hook.URL}}, 409)
	master.must("POST", "/api/v1/alert-channels", map[string]any{"name": "bad-" + sfx, "kind": "email", "config": map[string]any{}}, 400)
	ch2 := master.must("PATCH", "/api/v1/alert-channels/"+chID, map[string]any{"min_severity": "warning", "config": map[string]any{"url": ""}}, 200)
	if ch2["min_severity"] != "warning" || ch2["target"] != ch["target"] || ch2["has_signing_secret"] != true {
		t.Fatalf("channel patch: %v", ch2)
	}
	master.must("POST", "/api/v1/alert-channels/"+chID+"/test", nil, 200)
	member.must("GET", "/api/v1/alert-channels", nil, 403)
	master.must("GET", "/api/v1/alert-history?channel=api-ch-"+sfx, nil, 200)
	master.must("DELETE", "/api/v1/alert-channels/"+chID, nil, 200)
	master.must("GET", "/api/v1/alert-channels/"+chID, nil, 404)

	// --- audit trail ---
	audit := master.must("GET", "/api/v1/audit?q=via+API&limit=5", nil, 200)
	if audit["count"].(float64) == 0 {
		t.Fatal("no audit entries recorded")
	}
	// Unknown route → JSON 404.
	master.must("GET", "/api/v1/nope", nil, 404)
}
