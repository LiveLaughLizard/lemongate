package passthrough

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"lemongate/internal/auth"
)

func newTestRouter(t *testing.T, routes ...Route) (*Router, http.Handler) {
	t.Helper()
	p := New(nil, nil, nil, auth.NewResolver(nil, "master-secret"), nil)
	m := map[string]*live{}
	for _, r := range routes {
		r := r
		if err := Validate(&r); err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(r.TargetURL)
		m[r.Name] = &live{Route: r, target: u, secret: "upstream-secret"}
	}
	p.routes.Store(&m)
	mux := chi.NewRouter()
	p.Mount(mux)
	return p, mux
}

func TestForwarding(t *testing.T) {
	var got *http.Request
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(r.Context())
		w.Header().Set("X-Upstream", "yes")
		w.Header().Set("Connection", "close")
		w.WriteHeader(201)
		fmt.Fprint(w, "created")
	}))
	defer up.Close()
	_, h := newTestRouter(t, Route{Name: "svc", TargetURL: up.URL + "/api?fixed=1", AuthHeader: "X-Api-Token", AuthPrefix: "Token ",
		ExtraHeaders: map[string]string{"X-Team": "ml"}, Enabled: true})

	req := httptest.NewRequest("PUT", "/pt/svc/v2/items?q=a%20b", strings.NewReader(`{"a":1}`))
	req.Header.Set("Authorization", "Bearer client-key")
	req.Header.Set("Cookie", "lg_session=abc")
	req.Header.Set("Connection", "X-Drop-Me")
	req.Header.Set("X-Drop-Me", "1")
	req.Header.Set("X-Keep", "1")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != 201 || rr.Body.String() != "created" || rr.Header().Get("X-Upstream") != "yes" {
		t.Fatalf("response = %d %q %v", rr.Code, rr.Body.String(), rr.Header())
	}
	if rr.Header().Get("Connection") != "" {
		t.Fatal("hop-by-hop response header relayed")
	}
	if got.Method != "PUT" || got.URL.Path != "/api/v2/items" || got.URL.RawQuery != "fixed=1&q=a%20b" {
		t.Fatalf("upstream saw %s %s?%s", got.Method, got.URL.Path, got.URL.RawQuery)
	}
	if got.Header.Get("Authorization") != "" || got.Header.Get("Cookie") != "" || got.Header.Get("X-Drop-Me") != "" {
		t.Fatalf("client secrets leaked: %v", got.Header)
	}
	if got.Header.Get("X-Api-Token") != "Token upstream-secret" || got.Header.Get("X-Team") != "ml" || got.Header.Get("X-Keep") != "1" {
		t.Fatalf("headers = %v", got.Header)
	}
}

func TestRequireKeyAndErrors(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "" {
			t.Error("gateway key forwarded upstream")
		}
		fmt.Fprint(w, "ok")
	}))
	defer up.Close()
	_, h := newTestRouter(t,
		Route{Name: "locked", TargetURL: up.URL, RequireKey: true, Enabled: true},
		Route{Name: "off", TargetURL: up.URL, Enabled: false},
		Route{Name: "dead", TargetURL: "http://127.0.0.1:1", Enabled: true},
	)
	do := func(path string, hdr map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	errCode := func(rr *httptest.ResponseRecorder) string {
		var body struct{ Error struct{ Code string } }
		_ = json.Unmarshal(rr.Body.Bytes(), &body)
		return body.Error.Code
	}
	if rr := do("/pt/locked/x", nil); rr.Code != 401 || errCode(rr) != "invalid_api_key" {
		t.Fatalf("no key: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do("/pt/locked/x", map[string]string{"x-api-key": "master-secret"}); rr.Code != 200 || rr.Body.String() != "ok" {
		t.Fatalf("with key: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do("/pt/off/x", nil); rr.Code != 404 || errCode(rr) != "route_not_found" {
		t.Fatalf("disabled: %d", rr.Code)
	}
	if rr := do("/pt/nope", nil); rr.Code != 404 {
		t.Fatalf("unknown: %d", rr.Code)
	}
	if rr := do("/pt/dead/health", nil); rr.Code != 502 || errCode(rr) != "upstream_unreachable" {
		t.Fatalf("dead upstream: %d %s", rr.Code, rr.Body.String())
	}
}

func TestStreamingIsFlushed(t *testing.T) {
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		<-release
		fmt.Fprint(w, "data: two\n\n")
	}))
	defer up.Close()
	_, h := newTestRouter(t, Route{Name: "sse", TargetURL: up.URL, Enabled: true})
	gw := httptest.NewServer(h)
	defer gw.Close()

	resp, err := http.Get(gw.URL + "/pt/sse/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	first := make(chan string, 1)
	go func() { line, _ := br.ReadString('\n'); first <- line }()
	select {
	case line := <-first:
		if line != "data: one\n" {
			t.Fatalf("first line = %q", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first event was buffered instead of streamed")
	}
	close(release)
}

func TestValidate(t *testing.T) {
	for _, r := range []Route{
		{Name: "Bad Name", TargetURL: "http://x"},
		{Name: "ok", TargetURL: "ftp://x"},
		{Name: "ok", TargetURL: "/relative"},
		{Name: "ok", TargetURL: "http://user:pw@x"},
		{Name: "ok", TargetURL: "http://x", ExtraHeaders: map[string]string{"Host": "y"}},
		{Name: "ok", TargetURL: "http://x", AuthHeader: "bad header"},
		{Name: "ok", TargetURL: "http://x", CostPerRequest: -1},
	} {
		if err := Validate(&r); err == nil {
			t.Errorf("%+v should be invalid", r)
		}
	}
	r := Route{Name: " Tools ", TargetURL: "https://x/api"}
	if err := Validate(&r); err != nil || r.Name != "tools" || r.AuthHeader != "Authorization" {
		t.Fatalf("%v %+v", err, r)
	}
}

func TestJoinPath(t *testing.T) {
	for _, c := range [][3]string{{"", "", "/"}, {"/api", "", "/api"}, {"/api/", "v1/x", "/api/v1/x"}, {"", "health", "/health"}} {
		if got := joinPath(c[0], c[1]); got != c[2] {
			t.Errorf("joinPath(%q,%q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
}
