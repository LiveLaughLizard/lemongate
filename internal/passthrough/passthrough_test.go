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
	"lemongate/internal/spend"
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

func TestPathCleaning(t *testing.T) {
	var hits []string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.EscapedPath())
	}))
	defer up.Close()
	_, h := newTestRouter(t, Route{Name: "svc", TargetURL: up.URL + "/api", Enabled: true})

	for _, c := range []struct{ path, want string }{
		{"/pt/svc", "/api"},
		{"/pt/svc/", "/api/"},
		{"/pt/svc/x/", "/api/x/"},
		{"/pt/svc/x/../y", "/api/y"},
		{"/pt/svc/x/./y//z/", "/api/x/y/z/"},
		{"/pt/svc/c%20d", "/api/c%20d"},
		{"/pt/svc/100%25", "/api/100%25"},
		{"/pt/svc/a%2Fb/c%20d", "/api/a%2Fb/c%20d"},
		{"/pt/svc/x/%2e%2e/y", "/api/y"},
	} {
		hits = nil
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", c.path, nil))
		if rr.Code != 200 || len(hits) != 1 || hits[0] != c.want {
			t.Errorf("%s: %d, upstream saw %q, want %q", c.path, rr.Code, hits, c.want)
		}
	}
	for _, path := range []string{"/pt/svc/..", "/pt/svc/../../admin", "/pt/svc/x/../../admin", "/pt/svc/../api2/x",
		"/pt/svc/..%2f..%2fadmin", "/pt/svc/%2e%2e/admin", "/pt/svc/%2E%2E%2Fadmin"} {
		hits = nil
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
		if rr.Code != 400 || len(hits) != 0 {
			t.Errorf("%s: %d, upstream saw %q", path, rr.Code, hits)
		}
	}
}

func TestResponseHeadersSandboxed(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "lg_session=evil; Path=/")
		w.Header().Set("Set-Cookie2", "x=1")
		w.Header().Set("Content-Security-Policy", "default-src *")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<script>alert(1)</script>")
	}))
	defer up.Close()
	_, h := newTestRouter(t, Route{Name: "svc", TargetURL: up.URL, Enabled: true})
	// The app's security-headers middleware runs first and sets a console policy.
	outer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		h.ServeHTTP(w, r)
	})

	for _, path := range []string{"/pt/svc/page", "/pt/nope/page"} {
		rr := httptest.NewRecorder()
		outer.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
		if v := rr.Header().Values("Set-Cookie"); len(v) > 0 || rr.Header().Get("Set-Cookie2") != "" {
			t.Fatalf("%s: upstream cookies relayed: %v", path, rr.Header())
		}
		if v := rr.Header().Values("Content-Security-Policy"); len(v) != 1 || v[0] != "sandbox" {
			t.Fatalf("%s: CSP = %q", path, v)
		}
		if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s: missing nosniff", path)
		}
	}
}

func TestUpstreamErrorHidesURL(t *testing.T) {
	p, h := newTestRouter(t, Route{Name: "dead", TargetURL: "http://127.0.0.1:1/api?token=s3cret", Enabled: true})
	var recs []spend.Record
	p.spend = spend.NewWriter(nil)
	p.spend.Observe(func(r spend.Record) { recs = append(recs, r) })

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/pt/dead/tok3n/x?k=v", nil))
	var body struct{ Error struct{ Message string } }
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if rr.Code != 502 || body.Error.Message != "upstream request failed" {
		t.Fatalf("client got %d %s", rr.Code, rr.Body.String())
	}
	if len(recs) != 1 || !strings.HasPrefix(recs[0].Error, "upstream request failed: ") {
		t.Fatalf("records = %+v", recs)
	}
	for _, leak := range []string{"s3cret", "tok3n", "k=v"} {
		if strings.Contains(recs[0].Error, leak) {
			t.Fatalf("stored error leaks %q: %s", leak, recs[0].Error)
		}
	}
}

func TestWithin(t *testing.T) {
	for _, c := range []struct {
		p, base string
		ok      bool
	}{
		{"/api", "/api", true}, {"/api/", "/api", true}, {"/api/x", "/api/", true}, {"/x", "", true}, {"/x", "/", true},
		{"/", "/api", false}, {"/api2", "/api", false}, {"/admin", "/api/", false},
	} {
		if got := within(c.p, c.base); got != c.ok {
			t.Errorf("within(%q, %q) = %v", c.p, c.base, got)
		}
	}
}
