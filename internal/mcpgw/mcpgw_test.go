package mcpgw

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"lemongate/internal/auth"
	"lemongate/internal/mcpgw/mockupstream"
	"lemongate/internal/store"
)

// swappable lets a test replace an upstream (simulating a restart) behind a stable URL.
type swappable struct{ h atomic.Pointer[http.Handler] }

func (s *swappable) set(h http.Handler)                               { s.h.Store(&h) }
func (s *swappable) ServeHTTP(w http.ResponseWriter, r *http.Request) { (*s.h.Load()).ServeHTTP(w, r) }

type fixture struct {
	g      *Gateway
	url    string // gateway /mcp endpoint
	alpha  *swappable
	alphaM *mockupstream.Server
	mu     sync.Mutex
	keys   map[string]*auth.Principal
}

func (f *fixture) setKey(tok string, p *auth.Principal) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[tok] = p
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{keys: map[string]*auth.Principal{}}

	f.alphaM = mockupstream.New(mockupstream.Options{Name: "alpha"})
	f.alpha = &swappable{}
	f.alpha.set(f.alphaM.Handler())
	alphaSrv := httptest.NewServer(f.alpha)
	t.Cleanup(alphaSrv.Close)

	beta := mockupstream.New(mockupstream.Options{Name: "beta", Token: "beta-secret"})
	betaSrv := httptest.NewServer(beta.Handler())
	t.Cleanup(betaSrv.Close)

	g := New(nil, nil, nil)
	t.Cleanup(g.Close)
	g.authenticate = func(_ context.Context, tok string) (*auth.Principal, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if p, ok := f.keys[tok]; ok {
			return p, nil
		}
		return nil, auth.ErrInvalidKey
	}
	now := time.Now()
	g.apply([]Server{
		{ID: "1", Name: "alpha", URL: alphaSrv.URL + "/mcp", Transport: TransportHTTP, Enabled: true, UpdatedAt: now},
		{ID: "2", Name: "beta", URL: betaSrv.URL + "/sse", Transport: TransportSSE, Enabled: true, UpdatedAt: now,
			AuthHeader: "Authorization", AuthPrefix: "Bearer ", staticSecret: "beta-secret"},
		{ID: "3", Name: "gamma", URL: alphaSrv.URL + "/mcp", Transport: TransportHTTP, Enabled: false, AvailableToAll: true, UpdatedAt: now},
	})
	f.g = g

	f.setKey("master", &auth.Principal{Kind: "master", Role: auth.RoleAdmin})
	f.setKey("k-alpha", &auth.Principal{Kind: "key", Role: auth.RoleMember, Key: &store.Key{ID: "11111111-1111-1111-1111-111111111111", MCPServers: []string{"alpha"}}})
	f.setKey("k-team", &auth.Principal{Kind: "key", Role: auth.RoleMember, Key: &store.Key{ID: "k2"}, Team: &store.Team{MCPServers: []string{"beta"}}})
	f.setKey("k-none", &auth.Principal{Kind: "key", Role: auth.RoleMember, Key: &store.Key{ID: "k3"}})

	r := chi.NewRouter()
	g.Mount(r)
	gw := httptest.NewServer(r)
	t.Cleanup(gw.Close)
	f.url = gw.URL + "/mcp"
	return f
}

type bearer struct {
	tok  string
	base http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.tok)
	return b.base.RoundTrip(r)
}

func (f *fixture) connect(t *testing.T, tok string) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	cs, err := c.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: f.url,
		HTTPClient: &http.Client{Transport: bearer{tok, http.DefaultTransport}}, MaxRetries: -1}, nil)
	if err != nil {
		t.Fatalf("connect as %s: %v", tok, err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func toolNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var names []string
	for tool, err := range cs.Tools(ctx, nil) {
		if err != nil {
			t.Fatalf("list tools: %v", err)
		}
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	return names
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (*mcp.CallToolResult, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
}

func TestAggregationAndNamespacing(t *testing.T) {
	f := newFixture(t)
	cs := f.connect(t, "master")
	got := toolNames(t, cs)
	want := []string{"alpha__add_numbers", "alpha__always_fail", "alpha__echo", "alpha__lemon_facts",
		"beta__add_numbers", "beta__always_fail", "beta__echo", "beta__lemon_facts"}
	if !slices.Equal(got, want) {
		t.Fatalf("tools = %v, want %v", got, want)
	}

	// Descriptions and schemas are preserved.
	ctx := context.Background()
	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range res.Tools {
		if tool.Name != "alpha__add_numbers" {
			continue
		}
		if tool.Description != "Adds two numbers and returns the sum." {
			t.Errorf("description = %q", tool.Description)
		}
		b, _ := json.Marshal(tool.InputSchema)
		if !strings.Contains(string(b), `"a"`) || !strings.Contains(string(b), `"required"`) {
			t.Errorf("schema not preserved: %s", b)
		}
	}

	out, err := call(t, cs, "alpha__add_numbers", map[string]any{"a": 2, "b": 3.5})
	if err != nil {
		t.Fatal(err)
	}
	if out.IsError || len(out.Content) == 0 || out.Content[0].(*mcp.TextContent).Text != "2 + 3.5 = 5.5" {
		t.Fatalf("unexpected result: %+v", out)
	}
	sc, _ := json.Marshal(out.StructuredContent)
	if string(sc) != `{"sum":5.5}` {
		t.Errorf("structured content = %s", sc)
	}

	// SSE upstream with an auth header from the credential.
	out, err = call(t, cs, "beta__echo", map[string]any{"message": "hi", "uppercase": true, "repeat": 2})
	if err != nil {
		t.Fatal(err)
	}
	if txt := out.Content[0].(*mcp.TextContent).Text; txt != "HI HI" {
		t.Errorf("echo = %q", txt)
	}

	// Tool errors pass through as isError results.
	out, err = call(t, cs, "alpha__always_fail", map[string]any{"reason": "nope"})
	if err != nil {
		t.Fatal(err)
	}
	if !out.IsError || !strings.Contains(resultText(out), "nope") {
		t.Errorf("expected tool error, got %+v", out)
	}

	st := f.g.Status("alpha")
	if !st.Connected || st.ToolCount != 4 || st.State() != "ok" {
		t.Errorf("status = %+v", st)
	}
	if st := f.g.Status("gamma"); st.Connected || st.State() != "disabled" {
		t.Errorf("gamma status = %+v", st)
	}
}

func TestAccessControl(t *testing.T) {
	f := newFixture(t)

	if got := toolNames(t, f.connect(t, "k-alpha")); !slices.Equal(got, []string{"alpha__add_numbers", "alpha__always_fail", "alpha__echo", "alpha__lemon_facts"}) {
		t.Errorf("k-alpha tools = %v", got)
	}
	if got := toolNames(t, f.connect(t, "k-team")); len(got) != 4 || !strings.HasPrefix(got[0], "beta__") {
		t.Errorf("k-team tools = %v", got)
	}
	if got := toolNames(t, f.connect(t, "k-none")); len(got) != 0 {
		t.Errorf("k-none tools = %v", got)
	}

	cs := f.connect(t, "k-alpha")
	if _, err := call(t, cs, "beta__echo", map[string]any{"message": "x"}); err == nil {
		t.Error("k-alpha could call a beta tool")
	}
	if _, err := call(t, cs, "alpha__echo", map[string]any{"message": "x"}); err != nil {
		t.Errorf("k-alpha alpha call: %v", err)
	}

	// Access revoked mid-session is enforced on the next call.
	f.setKey("k-alpha", &auth.Principal{Kind: "key", Role: auth.RoleMember, Key: &store.Key{ID: "k1"}})
	_, err := call(t, cs, "alpha__echo", map[string]any{"message": "x"})
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("revoked call err = %v", err)
	}
}

func TestAuthentication(t *testing.T) {
	f := newFixture(t)
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}`
	do := func(hdr, val string) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, f.url, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if hdr != "" {
			req.Header.Set(hdr, val)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	if r := do("", ""); r.StatusCode != http.StatusUnauthorized || r.Header.Get("WWW-Authenticate") == "" {
		t.Errorf("no key: status %d", r.StatusCode)
	}
	if r := do("Authorization", "Bearer wrong"); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad key: status %d", r.StatusCode)
	}
	r := do("x-api-key", "master")
	if r.StatusCode != http.StatusOK || r.Header.Get("Mcp-Session-Id") == "" {
		t.Errorf("x-api-key: status %d, session %q", r.StatusCode, r.Header.Get("Mcp-Session-Id"))
	}

	// A session cannot be used with a different key.
	sid := r.Header.Get("Mcp-Session-Id")
	req, _ := http.NewRequest(http.MethodPost, f.url, strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer k-none")
	req.Header.Set("Mcp-Session-Id", sid)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("hijack: status %d", resp.StatusCode)
	}
}

func TestReconnectAfterUpstreamRestart(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.g.CallTool(ctx, "alpha", "echo", map[string]any{"message": "one"}); err != nil {
		t.Fatal(err)
	}
	// Replace the upstream: the old session id is unknown to the new instance.
	f.alpha.set(mockupstream.New(mockupstream.Options{Name: "alpha"}).Handler())
	res, err := f.g.CallTool(ctx, "alpha", "echo", map[string]any{"message": "two"})
	if err != nil {
		t.Fatalf("call after restart: %v", err)
	}
	if resultText(res) != "two" {
		t.Errorf("result = %q", resultText(res))
	}
	tools, err := f.g.ListServerTools(ctx, "alpha", true)
	if err != nil || len(tools) != 4 {
		t.Errorf("refresh: %d tools, err %v", len(tools), err)
	}
}

func TestToolListChangesPropagate(t *testing.T) {
	f := newFixture(t)
	cs := f.connect(t, "master")
	if n := len(toolNames(t, cs)); n != 8 {
		t.Fatalf("tools = %d", n)
	}
	f.alphaM.MCP().AddTool(&mcp.Tool{Name: "squeeze", InputSchema: map[string]any{"type": "object"}},
		func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "squeezed"}}}, nil
		})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if names := toolNames(t, cs); slices.Contains(names, "alpha__squeeze") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("new upstream tool never appeared")
		}
		time.Sleep(50 * time.Millisecond)
	}
	out, err := call(t, cs, "alpha__squeeze", nil)
	if err != nil || resultText(out) != "squeezed" {
		t.Fatalf("squeeze: %v %v", out, err)
	}
}

func TestUnreachableUpstream(t *testing.T) {
	f := newFixture(t)
	f.g.apply(append(f.g.snapshotConfigs(), Server{ID: "4", Name: "down", URL: "http://127.0.0.1:1/mcp", Transport: TransportHTTP, Enabled: true, AvailableToAll: true}))
	cs := f.connect(t, "k-none")
	if got := toolNames(t, cs); len(got) != 0 {
		t.Errorf("tools from unreachable server: %v", got)
	}
	st := f.g.Status("down")
	if st.State() != "error" || st.LastError == "" {
		t.Errorf("status = %+v", st)
	}
	if _, err := f.g.TestConnection(context.Background(), Server{Name: "down", URL: "http://127.0.0.1:1/mcp"}); err == nil {
		t.Error("TestConnection succeeded against a closed port")
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		s  Server
		ok bool
	}{
		{Server{Name: "docs-search", URL: "https://x.example/mcp"}, true},
		{Server{Name: "a_b", URL: "http://localhost:8101/mcp", Transport: "sse"}, true},
		{Server{Name: "Bad", URL: "http://x"}, false},
		{Server{Name: "a__b", URL: "http://x"}, false},
		{Server{Name: "has space", URL: "http://x"}, false},
		{Server{Name: "ok", URL: "ftp://x"}, false},
		{Server{Name: "ok", URL: "http://x", Transport: "stdio"}, false},
	}
	for _, c := range cases {
		err := c.s.Validate()
		if (err == nil) != c.ok {
			t.Errorf("%+v: err = %v", c.s, err)
		}
	}
	s := Server{Name: "x", URL: "http://x"}
	_ = s.Validate()
	if s.Transport != TransportHTTP || s.AuthHeader != "Authorization" {
		t.Errorf("defaults not applied: %+v", s)
	}
}

func TestObjectSchema(t *testing.T) {
	for in, want := range map[string]string{
		`null`:                                   `{"type":"object"}`,
		`{"properties":{"q":{"type":"string"}}}`: `{"properties":{"q":{"type":"string"}},"type":"object"}`,
		`{"type":"string"}`:                      `{"type":"object"}`,
	} {
		var v any
		_ = json.Unmarshal([]byte(in), &v)
		b, _ := json.Marshal(objectSchema(v))
		if string(b) != want {
			t.Errorf("objectSchema(%s) = %s, want %s", in, b, want)
		}
	}
}

func TestAllowed(t *testing.T) {
	s := Server{Name: "x", Enabled: true}
	member := &auth.Principal{Role: auth.RoleMember, Key: &store.Key{}}
	if Allowed(member, s) || Allowed(nil, s) {
		t.Error("member allowed without grant")
	}
	if !Allowed(&auth.Principal{Role: auth.RoleAdmin}, s) {
		t.Error("admin denied")
	}
	s.AvailableToAll = true
	if !Allowed(member, s) {
		t.Error("available_to_all denied")
	}
	s.Enabled = false
	if Allowed(&auth.Principal{Role: auth.RoleAdmin}, s) {
		t.Error("disabled server allowed")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHeaderTransportSameOriginOnly(t *testing.T) {
	var got string
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		got = r.Header.Get("X-Key")
		return &http.Response{StatusCode: 200, Body: http.NoBody, Request: r}, nil
	})
	server, _ := url.Parse("https://MCP.example.com/mcp")
	rt := &headerTransport{base: base, origin: origin(server), header: "X-Key", value: "s3cret"}
	for target, want := range map[string]string{
		"https://mcp.example.com/mcp":         "s3cret",
		"https://mcp.example.com:443/message": "s3cret",
		"http://mcp.example.com/mcp":          "",
		"https://mcp.example.com:8443/mcp":    "",
		"https://evil.example.net/mcp":        "",
		"https://mcp.example.com.evil.net/":   "",
	} {
		got = ""
		req, _ := http.NewRequest("GET", target, nil)
		if _, err := rt.RoundTrip(req); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s: header = %q, want %q", target, got, want)
		}
	}
}
