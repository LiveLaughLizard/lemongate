package app

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"lemongate/internal/auth"
	"lemongate/internal/config"
	"lemongate/internal/store"
)

// fakeUpstream imitates a vLLM server. When failing is set it returns 500s.
func fakeUpstream(t *testing.T, model string, failing *atomic.Bool, hits *atomic.Int64) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/models", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"object":"list","data":[{"id":%q}]}`, model)
	})
	mux.HandleFunc("POST /v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if failing != nil && failing.Load() {
			http.Error(w, `{"message":"boom"}`, 500)
			return
		}
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["model"] != model {
			http.Error(w, `{"message":"wrong model"}`, 404)
			return
		}
		if req["stream"] == true {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "data: {\"model\":%q,\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n", model)
			fmt.Fprintf(w, "data: {\"model\":%q,\"choices\":[],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":1}}\n\n", model)
			fmt.Fprint(w, "data: [DONE]\n\n")
			return
		}
		fmt.Fprintf(w, `{"model":%q,"choices":[{"index":0,"message":{"role":"assistant","content":"hello"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`, model)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestIntegrationGateway(t *testing.T) {
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
	in, out := 1.0, 2.0
	cfg := &config.Config{DatabaseURL: dsn, MasterKey: "test-master", SecretKey: "s", BaseURL: "http://test", SessionHours: 1,
		File: config.FileConfig{
			Models: []config.FileModel{
				{Name: "chat", APIBase: upA.URL + "/v1", UpstreamModel: "up-model", InputCostPerM: in, OutputCostPerM: out},
				{Name: "chat", APIBase: upB.URL, UpstreamModel: "up-model", InputCostPerM: in, OutputCostPerM: out},
				{Name: "other", APIBase: upB.URL, UpstreamModel: "up-model"},
			},
			Settings: map[string]any{"routing": map[string]any{"health_check_sec": 0, "retry_backoff_ms": 1, "num_retries": 3, "cooldown_failures": 1}},
		}}
	a, err := New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	bgCtx, cancel := context.WithCancel(ctx)
	wait := a.Run(bgCtx)
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()

	plain, hash, hint := auth.NewKey()
	budget := 1.0
	rpm := 4
	k, err := a.Store.CreateKey(ctx, store.Key{KeyHash: hash, KeyHint: hint, Alias: "it", Scope: "inference",
		Models: []string{"chat"}, Budget: store.Budget{MaxBudget: &budget}, Limits: store.Limits{RPMLimit: &rpm}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = a.Pool.Exec(context.Background(), `DELETE FROM request_logs WHERE key_id=$1`, k.ID)
		_, _ = a.Pool.Exec(context.Background(), `DELETE FROM api_keys WHERE id=$1`, k.ID)
	})

	post := func(key, body string) (*http.Response, string) {
		req, _ := http.NewRequest("POST", srv.URL+"/v1/chat/completions", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, string(b)
	}

	// Non-streaming: one replica fails, retries land on the healthy one; model name is rewritten.
	resp, body := post(plain, `{"model":"chat","messages":[{"role":"user","content":"hi"}]}`)
	if resp.StatusCode != 200 || !strings.Contains(body, `"model":"chat"`) {
		t.Fatalf("chat: %d %s", resp.StatusCode, body)
	}
	if hitsB.Load() == 0 {
		t.Fatal("healthy replica never received traffic")
	}
	if c := resp.Header.Get("x-lemongate-cost"); c != "0.00002000" {
		t.Fatalf("cost header = %q", c)
	}

	// Streaming: usage trailer is captured but hidden from a client that did not ask for it.
	req, _ := http.NewRequest("POST", srv.URL+"/v1/chat/completions", strings.NewReader(`{"model":"chat","stream":true,"messages":[]}`))
	req.Header.Set("Authorization", "Bearer "+plain)
	sresp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	sc := bufio.NewScanner(sresp.Body)
	for sc.Scan() {
		if l := sc.Text(); l != "" {
			lines = append(lines, l)
		}
	}
	sresp.Body.Close()
	if len(lines) != 2 || !strings.Contains(lines[0], `"model":"chat"`) || lines[1] != "data: [DONE]" {
		t.Fatalf("stream lines: %q", lines)
	}

	// Model access is enforced.
	if resp, body := post(plain, `{"model":"other","messages":[]}`); resp.StatusCode != 403 {
		t.Fatalf("expected 403, got %d %s", resp.StatusCode, body)
	}
	// Unknown key.
	if resp, _ := post("lg-nope", `{"model":"chat","messages":[]}`); resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	// Rate limit: 4 rpm. Two requests counted so far (403/401 are rejected before limits).
	post(plain, `{"model":"chat","messages":[]}`)
	post(plain, `{"model":"chat","messages":[]}`)
	if resp, body := post(plain, `{"model":"chat","messages":[]}`); resp.StatusCode != 429 || !strings.Contains(body, "rate_limit") {
		t.Fatalf("expected rate limit, got %d %s", resp.StatusCode, body)
	}

	// Spend is flushed to the key and rollups.
	deadline := time.Now().Add(5 * time.Second)
	for {
		var spend float64
		_ = a.Pool.QueryRow(ctx, `SELECT spend FROM api_keys WHERE id=$1`, k.ID).Scan(&spend)
		if spend > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("spend never recorded")
		}
		time.Sleep(200 * time.Millisecond)
	}
	var n int
	_ = a.Pool.QueryRow(ctx, `SELECT count(*) FROM request_logs WHERE key_id=$1`, k.ID).Scan(&n)
	if n < 4 {
		t.Fatalf("request_logs rows = %d", n)
	}

	// Budget: exhaust it and expect a budget error.
	if _, err := a.Pool.Exec(ctx, `UPDATE api_keys SET spend = 5, rpm_limit = NULL WHERE id=$1`, k.ID); err != nil {
		t.Fatal(err)
	}
	a.Resolver.Invalidate()
	if resp, body := post(plain, `{"model":"chat","messages":[]}`); resp.StatusCode != 429 || !strings.Contains(body, "budget") {
		t.Fatalf("expected budget error, got %d %s", resp.StatusCode, body)
	}
	cancel()
	wait()
}
