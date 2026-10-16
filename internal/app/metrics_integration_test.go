package app

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"lemongate/internal/auth"
	"lemongate/internal/config"
	"lemongate/internal/metrics"
	"lemongate/internal/settings"
	"lemongate/internal/store"
)

func TestIntegrationMetrics(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	var bad atomic.Bool
	var hitsA, hitsB atomic.Int64
	bad.Store(true)
	upA := fakeUpstream(t, "up-model", &bad, &hitsA)
	upB := fakeUpstream(t, "up-model", nil, &hitsB)
	cfg := &config.Config{DatabaseURL: dsn, MasterKey: "test-master", SecretKey: "s", BaseURL: "http://test", SessionHours: 1,
		File: config.FileConfig{
			Models: []config.FileModel{
				{Name: "metrics-chat", APIBase: upA.URL, UpstreamModel: "up-model", InputCostPerM: 1, OutputCostPerM: 2},
				{Name: "metrics-chat", APIBase: upB.URL, UpstreamModel: "up-model", InputCostPerM: 1, OutputCostPerM: 2},
			},
			// Weighted routing with a failing replica guarantees retries over a few calls.
			Settings: map[string]any{"routing": map[string]any{"health_check_sec": 0, "retry_backoff_ms": 1, "num_retries": 3, "cooldown_failures": 100}},
		}}
	a, err := New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err := a.Metrics.Revoke(ctx); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()

	plain, hash, hint := auth.NewKey()
	budget := 5.0
	if _, err := a.Store.CreateKey(ctx, store.Key{KeyHash: hash, KeyHint: hint, Alias: "metrics-it-key", Scope: "inference",
		Models: []string{"metrics-chat"}, Budget: store.Budget{MaxBudget: &budget}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		req, _ := http.NewRequest("POST", srv.URL+"/v1/chat/completions",
			strings.NewReader(`{"model":"metrics-chat","messages":[{"role":"user","content":"hi"}]}`))
		req.Header.Set("Authorization", "Bearer "+plain)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("chat call %d: status %d", i, resp.StatusCode)
		}
	}
	if hitsA.Load() == 0 {
		t.Fatal("expected the failing replica to be tried at least once")
	}

	scrape := func(token string) (int, string) {
		req, _ := http.NewRequest("GET", srv.URL+"/metrics", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	set := func(fn func(*settings.Metrics)) {
		if _, err := a.Settings.Update(ctx, func(s *settings.Settings) { fn(&s.Metrics) }); err != nil {
			t.Fatal(err)
		}
	}
	defer set(func(m *settings.Metrics) { *m = settings.Defaults().Metrics })

	// Open by default, with live and event metrics.
	set(func(m *settings.Metrics) { *m = settings.Defaults().Metrics })
	code, body := scrape("")
	if code != 200 {
		t.Fatalf("open scrape: %d", code)
	}
	for _, want := range []string{
		`lemongate_build_info{`,
		`lemongate_requests_total{model="metrics-chat",route="chat/completions",status="success"}`,
		`lemongate_upstream_requests_total{api_base="` + upB.URL + `",code="2xx",deployment="config-1",model="metrics-chat"}`,
		`lemongate_upstream_requests_total{api_base="` + upA.URL + `",code="5xx",deployment="config-0",model="metrics-chat"}`,
		`lemongate_retries_total{model="metrics-chat"}`,
		`lemongate_deployment_inflight{api_base="` + upB.URL + `",deployment="config-1",model="metrics-chat"} 0`,
		`lemongate_deployment_cooling_down{`,
		`lemongate_deployments{model="metrics-chat"} 2`,
		`lemongate_spend_log_queue_depth `,
		`lemongate_cache_entries `,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape is missing %s", want)
		}
	}
	if strings.Contains(body, "lemongate_key_spend_usd") {
		t.Error("entity metrics exported while disabled")
	}

	// Disabled → 404.
	set(func(m *settings.Metrics) { m.Enabled = false })
	if code, _ := scrape(""); code != 404 {
		t.Errorf("disabled scrape: %d, want 404", code)
	}

	// Auth required: no token → 401, master key → 200, generated token → 200, revoked → 401.
	set(func(m *settings.Metrics) { m.Enabled, m.RequireAuth, m.EntityMetrics = true, true, true })
	if code, _ := scrape(""); code != 401 {
		t.Errorf("unauthenticated scrape: %d, want 401", code)
	}
	if code, _ := scrape("lgm-wrong"); code != 401 {
		t.Errorf("wrong token: %d, want 401", code)
	}
	if code, _ := scrape("test-master"); code != 200 {
		t.Errorf("master key scrape: %d, want 200", code)
	}
	token, err := a.Metrics.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	code, body = scrape(token)
	if code != 200 {
		t.Fatalf("token scrape: %d", code)
	}
	if !strings.Contains(body, `key_alias="metrics-it-key"`) || !strings.Contains(body, "lemongate_key_budget_usd{") {
		t.Error("entity metrics missing for the test key")
	}
	req, _ := http.NewRequest("GET", srv.URL+"/metrics", nil)
	req.SetBasicAuth("prometheus", token)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 200 {
		t.Errorf("basic-auth scrape failed: %v %v", err, resp)
	}

	// A second process (another replica) sees the rotated token through the database.
	other := metrics.NewEndpoint(a.Pool, a.Settings, "", "")
	if err := other.Load(ctx); err != nil || !other.HasToken() {
		t.Errorf("token hash not persisted: %v", err)
	}
	if err := a.Metrics.Revoke(ctx); err != nil {
		t.Fatal(err)
	}
	if code, _ := scrape(token); code != 401 {
		t.Errorf("revoked token scrape: %d, want 401", code)
	}
}
