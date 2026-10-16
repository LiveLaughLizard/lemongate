package mcpgw

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	connectTimeout = 15 * time.Second
	listTimeout    = 20 * time.Second
	// errorBackoff suppresses repeated tool list fetches against a failing upstream.
	errorBackoff = 15 * time.Second
)

// upstream is a lazily connected client session to one registered MCP server.
type upstream struct {
	g   *Gateway
	cfg Server

	connMu sync.Mutex // serialises connects

	mu          sync.Mutex
	session     *mcp.ClientSession
	cancel      context.CancelFunc
	connectedAt time.Time
	lastErr     string
	lastErrAt   time.Time
	closed      bool

	toolsMu    sync.Mutex // serialises tool list fetches; the fields below are guarded by mu
	tools      []*mcp.Tool
	toolsAt    time.Time
	toolsErrAt time.Time
	toolsGen   uint64 // bumped whenever the tool list changes
	stale      bool   // upstream announced tools/list_changed
}

func newUpstream(g *Gateway, cfg Server) *upstream { return &upstream{g: g, cfg: cfg} }

// headerTransport injects the upstream auth header into every request.
type headerTransport struct {
	base   http.RoundTripper
	header string
	value  string
}

func (t *headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set(t.header, t.value)
	return t.base.RoundTrip(r)
}

// dial opens a new client session for cfg. The session lives until cancel is called.
func (g *Gateway) dial(ctx context.Context, cfg Server, onToolsChanged func()) (*mcp.ClientSession, context.CancelFunc, error) {
	secret, err := g.secretFor(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}
	var rt http.RoundTripper = g.httpTransport
	if secret != "" {
		rt = &headerTransport{base: rt, header: cfg.AuthHeader, value: cfg.AuthPrefix + secret}
	}
	hc := &http.Client{Transport: rt}
	var t mcp.Transport
	if cfg.Transport == TransportSSE {
		t = &mcp.SSEClientTransport{Endpoint: cfg.URL, HTTPClient: hc}
	} else {
		t = &mcp.StreamableClientTransport{Endpoint: cfg.URL, HTTPClient: hc, MaxRetries: 2}
	}
	opts := &mcp.ClientOptions{Capabilities: &mcp.ClientCapabilities{}}
	if onToolsChanged != nil {
		opts.ToolListChangedHandler = func(context.Context, *mcp.ToolListChangedRequest) { onToolsChanged() }
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "lemongate", Title: "LemonGate MCP gateway", Version: g.version}, opts)

	// The SSE transport ties its event stream to the connect context, so the
	// session context must outlive this call. The timer bounds the handshake.
	sctx, cancel := context.WithCancel(g.ctx)
	timer := time.AfterFunc(connectTimeout, cancel)
	stopParent := context.AfterFunc(ctx, cancel)
	cs, err := client.Connect(sctx, t, nil)
	stopParent()
	if !timer.Stop() && err == nil {
		err = errors.New("connect timed out")
		_ = cs.Close()
	}
	if err != nil {
		cancel()
		if sctx.Err() != nil && ctx.Err() == nil {
			err = fmt.Errorf("connect timed out after %s", connectTimeout)
		}
		return nil, nil, err
	}
	return cs, cancel, nil
}

// conn returns the live session, connecting if needed.
func (u *upstream) conn(ctx context.Context) (*mcp.ClientSession, error) {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return nil, errors.New("server removed")
	}
	if s := u.session; s != nil {
		u.mu.Unlock()
		return s, nil
	}
	u.mu.Unlock()

	u.connMu.Lock()
	defer u.connMu.Unlock()
	u.mu.Lock()
	if s := u.session; s != nil {
		u.mu.Unlock()
		return s, nil
	}
	u.mu.Unlock()

	cs, cancel, err := u.g.dial(ctx, u.cfg, u.toolsChanged)
	u.mu.Lock()
	defer u.mu.Unlock()
	if err != nil {
		u.lastErr, u.lastErrAt = err.Error(), time.Now()
		return nil, err
	}
	if u.closed {
		_ = cs.Close()
		cancel()
		return nil, errors.New("server removed")
	}
	u.session, u.cancel, u.connectedAt = cs, cancel, time.Now()
	u.lastErr = ""
	go u.watch(cs)
	return cs, nil
}

// watch forgets the session when the upstream closes it so the next use reconnects.
func (u *upstream) watch(cs *mcp.ClientSession) {
	_ = cs.Wait()
	u.drop(cs, nil)
}

// drop discards a session (if still current), recording err.
func (u *upstream) drop(cs *mcp.ClientSession, err error) {
	u.mu.Lock()
	if err != nil {
		u.lastErr, u.lastErrAt = err.Error(), time.Now()
	}
	if u.session != cs || cs == nil {
		u.mu.Unlock()
		return
	}
	cancel := u.cancel
	u.session, u.cancel = nil, nil
	u.mu.Unlock()
	go func() {
		_ = cs.Close()
		if cancel != nil {
			cancel()
		}
	}()
}

func (u *upstream) close() {
	u.mu.Lock()
	u.closed = true
	cs := u.session
	u.mu.Unlock()
	u.drop(cs, nil)
}

func (u *upstream) toolsChanged() {
	u.mu.Lock()
	u.stale = true
	u.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(u.g.ctx, listTimeout)
		defer cancel()
		if _, err := u.listTools(ctx, false); err == nil {
			u.g.syncViews(ctx)
		}
	}()
}

// cachedTools answers from the cache when possible. done reports whether the
// caller can return (tools, err) without fetching.
func (u *upstream) cachedTools(refresh bool, since time.Time) (tools []*mcp.Tool, err error, done bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	now := time.Now()
	if refresh {
		// Another caller completed a fetch while we waited: reuse it.
		if !since.IsZero() && u.toolsAt.After(since) {
			return u.tools, nil, true
		}
		return nil, nil, false
	}
	if !u.stale && u.tools != nil && now.Sub(u.toolsAt) < u.g.ToolTTL {
		return u.tools, nil, true
	}
	if now.Sub(u.toolsErrAt) < errorBackoff {
		if u.tools != nil {
			return u.tools, nil, true
		}
		return nil, errors.New(u.lastErr), true
	}
	return nil, nil, false
}

// listTools returns the (cached) tool list. refresh forces a fetch. On a failed
// fetch the previous list, if any, is returned together with the error.
func (u *upstream) listTools(ctx context.Context, refresh bool) ([]*mcp.Tool, error) {
	if tools, err, done := u.cachedTools(refresh, time.Time{}); done {
		return tools, err
	}
	start := time.Now()
	u.toolsMu.Lock()
	defer u.toolsMu.Unlock()
	if tools, err, done := u.cachedTools(refresh, start); done {
		return tools, err
	}
	ctx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()
	var tools []*mcp.Tool
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		var cs *mcp.ClientSession
		cs, err = u.conn(ctx)
		if err != nil {
			break
		}
		tools, err = collectTools(ctx, cs)
		if err == nil {
			break
		}
		u.drop(cs, err)
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if err != nil {
		u.toolsErrAt = time.Now()
		u.lastErr, u.lastErrAt = err.Error(), u.toolsErrAt
		return u.tools, err
	}
	if u.tools == nil || !sameTools(u.tools, tools) {
		u.toolsGen++
	}
	u.tools, u.toolsAt, u.toolsErrAt, u.stale = tools, time.Now(), time.Time{}, false
	return tools, nil
}

func (u *upstream) gen() uint64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.toolsGen
}

func collectTools(ctx context.Context, cs *mcp.ClientSession) ([]*mcp.Tool, error) {
	tools := []*mcp.Tool{}
	for t, err := range cs.Tools(ctx, nil) {
		if err != nil {
			return nil, err
		}
		tools = append(tools, t)
	}
	return tools, nil
}

func sameTools(a, b []*mcp.Tool) bool {
	if len(a) != len(b) {
		return false
	}
	ja, err1 := json.Marshal(a)
	jb, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(ja) == string(jb)
}

// callTool forwards a call. Retries once on a fresh session when the old one
// turned out to be gone before the request was processed.
func (u *upstream) callTool(ctx context.Context, tool string, args any) (*mcp.CallToolResult, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		cs, err := u.conn(ctx)
		if err != nil {
			return nil, err
		}
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
		if err == nil {
			return res, nil
		}
		lastErr = err
		var rpcErr *jsonrpc.Error
		if errors.As(err, &rpcErr) || ctx.Err() != nil {
			// Protocol-level errors (unknown tool, invalid params) keep the session.
			return nil, err
		}
		u.drop(cs, err)
		if !errors.Is(err, mcp.ErrConnectionClosed) && !errors.Is(err, mcp.ErrSessionMissing) {
			return nil, err
		}
	}
	return nil, lastErr
}

// Status describes an upstream connection.
type Status struct {
	Known       bool      `json:"known"`
	Enabled     bool      `json:"enabled"`
	Connected   bool      `json:"connected"`
	ConnectedAt time.Time `json:"connected_at"`
	LastError   string    `json:"last_error"`
	LastErrorAt time.Time `json:"last_error_at"`
	ToolCount   int       `json:"tool_count"`
	ToolsAt     time.Time `json:"tools_at"`
}

// State is a one-word summary for status dots: ok | error | idle | disabled | unknown.
func (s Status) State() string {
	switch {
	case !s.Known:
		return "unknown"
	case !s.Enabled:
		return "disabled"
	case s.LastError != "" && (!s.Connected || s.LastErrorAt.After(s.ConnectedAt)):
		return "error"
	case s.Connected || s.ToolCount > 0:
		return "ok"
	}
	return "idle"
}

func (u *upstream) status() Status {
	u.mu.Lock()
	st := Status{Known: true, Enabled: u.cfg.Enabled, Connected: u.session != nil, ConnectedAt: u.connectedAt,
		LastError: u.lastErr, LastErrorAt: u.lastErrAt, ToolCount: len(u.tools), ToolsAt: u.toolsAt}
	u.mu.Unlock()
	return st
}
