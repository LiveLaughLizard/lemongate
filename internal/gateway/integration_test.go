package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"lemongate/internal/auth"
	"lemongate/internal/config"
	"lemongate/internal/db"
	"lemongate/internal/limits"
	"lemongate/internal/routing"
	"lemongate/internal/secret"
	"lemongate/internal/settings"
	"lemongate/internal/spend"
	"lemongate/internal/store"
)

// billingUpstream imitates vLLM for the routes the billing tests touch.
func billingUpstream(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["stream"] != true {
			fmt.Fprint(w, `{"model":"up","choices":[{"index":0,"message":{"role":"assistant","content":"hello"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 0; i < 3; i++ {
			fmt.Fprint(w, "data: {\"model\":\"up\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hello \"}}]}\n\n")
		}
		w.(http.Flusher).Flush()
		if u, _ := req["user"].(string); strings.HasSuffix(u, "-hang") {
			<-r.Context().Done() // never sends usage; the client disconnects
			return
		}
		fmt.Fprint(w, "data: {\"model\":\"up\",\"choices\":[],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":3}}\n\ndata: [DONE]\n\n")
	})
	mux.HandleFunc("POST /v1/responses", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		usage := `{"input_tokens":7,"input_tokens_details":{"cached_tokens":0},"output_tokens":3,"total_tokens":10}`
		if req["stream"] != true {
			fmt.Fprintf(w, `{"id":"resp_1","object":"response","model":"up","status":"completed","output":[],"usage":%s}`, usage)
			return
		}
		if _, ok := req["stream_options"]; ok {
			http.Error(w, `{"error":{"message":"stream_options not supported"}}`, 400)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"model\":\"up\",\"status\":\"in_progress\",\"usage\":null}}\n\n")
		fmt.Fprint(w, "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n")
		fmt.Fprintf(w, "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"model\":\"up\",\"status\":\"completed\",\"usage\":%s}}\n\n", usage)
	})
	mux.HandleFunc("POST /v1/embeddings", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"object\":\"list\"}\n\n")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestIntegrationBillingHardening(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, dsn)
	if err != nil {
		t.Skipf("database unavailable: %v", err)
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	model := "gwtest-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	dead := model + "-dead"
	t.Cleanup(func() {
		for _, q := range []string{`DELETE FROM request_logs WHERE model LIKE $1 || '%'`, `DELETE FROM daily_spend WHERE model LIKE $1 || '%'`,
			`DELETE FROM daily_tag_spend WHERE model LIKE $1 || '%'`, `DELETE FROM end_users WHERE id LIKE $1 || '%'`} {
			_, _ = pool.Exec(context.Background(), q, model)
		}
	})

	up := billingUpstream(t)
	st := store.New(pool)
	sets := settings.NewStore(pool)
	box, _ := secret.New("test-secret")
	reg := routing.NewRegistry(st, box, config.FileConfig{Models: []config.FileModel{
		{Name: model, APIBase: up.URL, UpstreamModel: "up", InputCostPerM: 1, OutputCostPerM: 2},
		{Name: dead, APIBase: "http://127.0.0.1:1", UpstreamModel: "up"},
	}}, sets)
	if err := reg.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	sw := spend.NewWriter(pool)
	wctx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { sw.Run(wctx); close(done) }()
	defer func() { stop(); <-done }()
	const masterKey = "lg-test-master-gw"
	g := New(&Gateway{Store: st, Resolver: auth.NewResolver(st, masterKey), Registry: reg, Limiter: limits.New(), Spend: sw, Settings: sets})
	r := chi.NewRouter()
	g.Mount(r)
	srv := httptest.NewServer(r)
	defer srv.Close()

	post := func(ctx context.Context, path, body string) *http.Response {
		req, _ := http.NewRequestWithContext(ctx, "POST", srv.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+masterKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	call := func(path, body string, want int) (string, string) {
		t.Helper()
		resp := post(ctx, path, body)
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("%s %s: %d %s", path, body, resp.StatusCode, b)
		}
		return resp.Header.Get("x-lemongate-request-id"), string(b)
	}
	msgs := `"messages":[{"role":"user","content":"hi there"}]`

	// NULs in end user, tags and metadata are stripped; the request is billed.
	nulID, _ := call("/v1/chat/completions", `{"model":"`+model+`",`+msgs+`,"user":"`+model+`-eu\u0000","tags":["`+model+`\u0000"],
		"metadata":{"k\u0000":"v\u0000","lit":"\\u0000","context_fallback_from":"spoof","deep":{"a":["\u0000"]}}}`, 200)
	plainID, _ := call("/v1/chat/completions", `{"model":"`+model+`",`+msgs+`}`, 200)
	// Non-boolean stream is refused before reaching upstream.
	call("/v1/chat/completions", `{"model":"`+model+`",`+msgs+`,"stream":"true"}`, 400)
	call("/v1/chat/completions", `{"model":"`+model+`",`+msgs+`,"stream":1}`, 400)
	// Responses API: streamed usage comes from response.completed; no stream_options injected.
	respStreamID, sse := call("/v1/responses", `{"model":"`+model+`","input":"hi","stream":true}`, 200)
	if !strings.Contains(sse, "response.completed") || !strings.Contains(sse, `"model":"`+model+`"`) {
		t.Fatalf("responses stream: %s", sse)
	}
	respID, _ := call("/v1/responses", `{"model":"`+model+`","input":"hi"}`, 200)
	// A non-JSON 2xx on a billable route is not relayed as a free success.
	embID, embBody := call("/v1/embeddings", `{"model":"`+model+`","input":"hi"}`, 502)
	if strings.Contains(embBody, "data:") {
		t.Fatalf("non-JSON body relayed: %s", embBody)
	}
	// Transport errors do not reveal the upstream address.
	deadID, deadBody := call("/v1/chat/completions", `{"model":"`+dead+`",`+msgs+`}`, 502)
	if strings.Contains(deadBody, "127.0.0.1") {
		t.Fatalf("upstream address leaked: %s", deadBody)
	}

	// A client that disconnects before the usage trailer is billed an estimate.
	cctx, cancel := context.WithCancel(ctx)
	resp := post(cctx, "/v1/chat/completions", `{"model":"`+model+`",`+msgs+`,"stream":true,"user":"`+model+`-hang"}`)
	hangID := resp.Header.Get("x-lemongate-request-id")
	sc := bufio.NewScanner(resp.Body)
	for seen := 0; seen < 3 && sc.Scan(); {
		if strings.HasPrefix(sc.Text(), "data:") {
			seen++
		}
	}
	cancel()
	resp.Body.Close()

	type row struct {
		status, endUser, errText string
		httpStatus, pt, ct       int
		cost                     float64
		tags                     []string
		md                       map[string]any
	}
	get := func(id string) row {
		t.Helper()
		var x row
		deadline := time.Now().Add(10 * time.Second)
		for {
			err := pool.QueryRow(ctx, `SELECT status, end_user, error, http_status, prompt_tokens, completion_tokens, cost, tags, metadata
				FROM request_logs WHERE request_id = $1`, id).Scan(&x.status, &x.endUser, &x.errText, &x.httpStatus, &x.pt, &x.ct, &x.cost, &x.tags, &x.md)
			if err == nil {
				return x
			}
			if time.Now().After(deadline) {
				t.Fatalf("request %s never logged: %v", id, err)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	if x := get(nulID); x.cost <= 0 || x.endUser != model+"-eu" || len(x.tags) != 1 || x.tags[0] != model ||
		x.md["k"] != "v" || x.md["lit"] != `\u0000` || x.md["context_fallback_from"] != nil {
		t.Fatalf("NUL request logged as %+v", x)
	}
	if x := get(plainID); x.cost <= 0 {
		t.Fatalf("plain request logged as %+v", x)
	}
	for _, id := range []string{respStreamID, respID} {
		if x := get(id); x.pt != 7 || x.ct != 3 || x.cost <= 0 {
			t.Fatalf("responses request %s logged as %+v", id, x)
		}
	}
	if x := get(embID); x.status != "error" || x.httpStatus != 502 {
		t.Fatalf("non-JSON response logged as %+v", x)
	}
	if x := get(deadID); !strings.Contains(x.errText, "127.0.0.1:1") {
		t.Fatalf("stored error should keep the detail: %+v", x)
	}
	if x := get(hangID); x.md["usage_estimated"] != true || x.ct < 3 || x.pt <= 0 || x.cost <= 0 || x.status != "success" {
		t.Fatalf("disconnected stream logged as %+v", x)
	}
}
