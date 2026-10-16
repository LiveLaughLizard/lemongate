// Package mcpgw aggregates upstream MCP servers behind a single /mcp endpoint.
//
// Clients connect with an API key over Streamable HTTP. Each caller sees the
// tools of the servers it may use, namespaced as "<server>__<tool>"; calls are
// proxied to a shared, lazily connected client session per upstream server and
// logged to mcp_tool_calls.
package mcpgw

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"lemongate/internal/auth"
	"lemongate/internal/metrics"
	"lemongate/internal/secret"
	"lemongate/internal/store"
)

// DefaultToolTTL is how long upstream tool lists are cached.
const DefaultToolTTL = 5 * time.Minute

// Gateway serves /mcp and manages upstream MCP server connections.
type Gateway struct {
	store    *store.Store
	box      *secret.Box
	resolver *auth.Resolver

	// ToolTTL controls tool list caching (default DefaultToolTTL).
	ToolTTL time.Duration
	version string

	// authenticate resolves an API token (replaceable in tests).
	authenticate func(ctx context.Context, token string) (*auth.Principal, error)

	ctx           context.Context
	cancel        context.CancelFunc
	httpTransport http.RoundTripper
	handler       http.Handler

	mu   sync.RWMutex
	ups  map[string]*upstream
	cfgs []Server

	viewsMu sync.Mutex
	views   map[string]*view

	calls    chan callRecord
	logDone  chan struct{}
	closeOne sync.Once
}

// New builds the gateway. Call Reload to load server definitions.
func New(s *store.Store, box *secret.Box, resolver *auth.Resolver) *Gateway {
	ctx, cancel := context.WithCancel(context.Background())
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = 2 * time.Minute
	g := &Gateway{store: s, box: box, resolver: resolver, ToolTTL: DefaultToolTTL, version: "1.0.0",
		ctx: ctx, cancel: cancel, httpTransport: tr,
		ups: map[string]*upstream{}, views: map[string]*view{},
		calls: make(chan callRecord, 2048), logDone: make(chan struct{})}
	if resolver != nil {
		g.authenticate = resolver.ResolveKey
	}
	streamable := mcp.NewStreamableHTTPHandler(g.getServer, &mcp.StreamableHTTPOptions{
		SessionTimeout: 30 * time.Minute,
		// Every request carries an API key, so DNS-rebinding protection would only
		// break deployments behind a local reverse proxy.
		DisableLocalhostProtection: true,
		Logger:                     slog.Default().With("component", "mcpgw"),
	})
	g.handler = sdkauth.RequireBearerToken(g.verifyToken, &sdkauth.RequireBearerTokenOptions{AllowMissingExpiration: true})(streamable)
	go g.logLoop()
	return g
}

// Close disconnects all upstreams and flushes the call log.
func (g *Gateway) Close() {
	g.closeOne.Do(func() {
		g.mu.Lock()
		for _, u := range g.ups {
			u.close()
		}
		g.mu.Unlock()
		g.cancel()
		<-g.logDone
	})
}

// Reload re-reads server definitions from the database. Connections to servers
// whose configuration did not change are kept.
func (g *Gateway) Reload(ctx context.Context) error {
	if g.store == nil {
		return nil
	}
	list, err := g.ListServers(ctx)
	if err != nil {
		return err
	}
	g.apply(list)
	return nil
}

func (g *Gateway) reloadLogged(ctx context.Context) {
	if err := g.Reload(ctx); err != nil {
		slog.Error("reload MCP servers", "err", err)
	}
}

// apply installs a new set of server definitions.
func (g *Gateway) apply(list []Server) {
	g.mu.Lock()
	next := make(map[string]*upstream, len(list))
	for _, s := range list {
		if u, ok := g.ups[s.Name]; ok && sameConn(u.cfg, s) {
			u.mu.Lock()
			u.cfg = s // non-connection fields (description, access) may change
			u.mu.Unlock()
			next[s.Name] = u
			continue
		}
		next[s.Name] = newUpstream(g, s)
	}
	for name, u := range g.ups {
		if next[name] != u {
			u.close()
		}
	}
	g.ups, g.cfgs = next, append([]Server(nil), list...)
	g.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(g.ctx, time.Minute)
		defer cancel()
		g.warm(ctx, next)
		g.syncViews(ctx)
	}()
}

// warm lists the tools of enabled servers in the background so the console and
// the first client session find a populated cache.
func (g *Gateway) warm(ctx context.Context, ups map[string]*upstream) {
	var wg sync.WaitGroup
	for _, u := range ups {
		if !u.config().Enabled {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = u.listTools(ctx, false)
		}()
	}
	wg.Wait()
}

func sameConn(a, b Server) bool {
	return a.ID == b.ID && a.URL == b.URL && a.Transport == b.Transport && store.Deref(a.CredentialID) == store.Deref(b.CredentialID) &&
		a.AuthHeader == b.AuthHeader && a.AuthPrefix == b.AuthPrefix && a.UpdatedAt.Equal(b.UpdatedAt) && a.staticSecret == b.staticSecret
}

func (g *Gateway) upstream(name string) *upstream {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.ups[name]
}

func (g *Gateway) snapshotConfigs() []Server {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return append([]Server(nil), g.cfgs...)
}

// Mount registers /mcp (POST for messages, GET for the event stream, DELETE to end a session).
func (g *Gateway) Mount(r chi.Router) {
	r.Handle("/mcp", g)
	r.Handle("/mcp/", g)
}

// --- authentication ---

type principalKey struct{}

// ServeHTTP authenticates the API key and hands the request to the MCP transport.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tok := auth.BearerToken(r.Header)
	var p *auth.Principal
	err := auth.ErrNoCredentials
	if tok != "" && g.authenticate != nil {
		p, err = g.authenticate(r.Context(), tok)
	}
	if err != nil {
		status, msg := http.StatusUnauthorized, err.Error()
		if !errors.Is(err, auth.ErrNoCredentials) && !errors.Is(err, auth.ErrInvalidKey) &&
			!errors.Is(err, auth.ErrKeyBlocked) && !errors.Is(err, auth.ErrKeyExpired) && !errors.Is(err, auth.ErrOwnerBlocked) {
			status, msg = http.StatusInternalServerError, "authentication failed"
			slog.Error("mcp auth", "err", err)
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="lemongate"`)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"message": msg, "type": "authentication_error"}})
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), principalKey{}, p))
	if h := r.Header.Get("Authorization"); len(h) < 7 || !strings.EqualFold(h[:7], "bearer ") {
		// Keys sent as x-api-key / api-key are normalised for the SDK middleware.
		r.Header = r.Header.Clone()
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	g.handler.ServeHTTP(w, r)
}

// verifyToken exposes the already resolved principal to the SDK. UserID binds
// sessions to the key that created them.
func (g *Gateway) verifyToken(ctx context.Context, token string, _ *http.Request) (*sdkauth.TokenInfo, error) {
	p, _ := ctx.Value(principalKey{}).(*auth.Principal)
	if p == nil {
		return nil, sdkauth.ErrInvalidToken
	}
	return &sdkauth.TokenInfo{UserID: auth.HashToken(token), Extra: map[string]any{"principal": p}}, nil
}

func principalFromExtra(extra *mcp.RequestExtra) *auth.Principal {
	if extra == nil || extra.TokenInfo == nil {
		return nil
	}
	p, _ := extra.TokenInfo.Extra["principal"].(*auth.Principal)
	return p
}

// Allowed reports whether an API principal may use server s: admins (master key,
// admin-scoped keys) may use every enabled server; others need the server to be
// available to all or listed on their key or team.
func Allowed(p *auth.Principal, s Server) bool {
	if p == nil || !s.Enabled {
		return false
	}
	if p.IsAdmin() || s.AvailableToAll {
		return true
	}
	if p.Key != nil && slices.Contains(p.Key.MCPServers, s.Name) {
		return true
	}
	return p.Team != nil && slices.Contains(p.Team.MCPServers, s.Name)
}

// VisibleServers lists the enabled servers an API principal may use.
func (g *Gateway) VisibleServers(p *auth.Principal) []Server {
	var out []Server
	for _, s := range g.snapshotConfigs() {
		if Allowed(p, s) {
			out = append(out, s)
		}
	}
	return out
}

// --- per-access-set MCP servers ---

// view is the aggregated MCP server presented to callers with one access set.
type view struct {
	g     *Gateway
	all   bool     // admin view: every enabled server
	names []string // allowed servers (when !all)
	srv   *mcp.Server

	mu  sync.Mutex
	reg map[string]viewEntry // upstream name -> registered tools
}

type viewEntry struct {
	u     *upstream
	gen   uint64
	tools []string // namespaced names
}

const maxViews = 512

func (g *Gateway) viewFor(p *auth.Principal) *view {
	key, all := "*", p.IsAdmin()
	var names []string
	if !all {
		for _, s := range g.VisibleServers(p) {
			names = append(names, s.Name)
		}
		sort.Strings(names)
		key = "=" + strings.Join(names, ",")
	}
	g.viewsMu.Lock()
	defer g.viewsMu.Unlock()
	if v, ok := g.views[key]; ok {
		return v
	}
	if len(g.views) >= maxViews {
		// Existing sessions keep their server; new sessions get fresh views.
		g.views = map[string]*view{}
	}
	v := &view{g: g, all: all, names: names, reg: map[string]viewEntry{}}
	v.srv = mcp.NewServer(&mcp.Implementation{Name: "lemongate", Title: "LemonGate MCP gateway", Version: g.version},
		&mcp.ServerOptions{
			Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{ListChanged: true}},
			Instructions: "Tools are provided by upstream MCP servers and named <server>__<tool>.",
			Logger:       slog.Default().With("component", "mcpgw"),
		})
	v.srv.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method == "tools/list" {
				v.sync(ctx)
			}
			return next(ctx, method, req)
		}
	})
	g.views[key] = v
	return v
}

// getServer picks the MCP server for a request. New sessions get freshly synced tools.
func (g *Gateway) getServer(r *http.Request) *mcp.Server {
	p, _ := r.Context().Value(principalKey{}).(*auth.Principal)
	if p == nil {
		return nil
	}
	v := g.viewFor(p)
	if r.Method == http.MethodPost && r.Header.Get("Mcp-Session-Id") == "" {
		v.sync(r.Context())
	}
	return v.srv
}

// syncViews brings every view up to date with the upstream tool caches.
func (g *Gateway) syncViews(ctx context.Context) {
	g.viewsMu.Lock()
	vs := make([]*view, 0, len(g.views))
	for _, v := range g.views {
		vs = append(vs, v)
	}
	g.viewsMu.Unlock()
	for _, v := range vs {
		v.sync(ctx)
	}
}

// sync registers the tools of the view's upstreams, fetching stale lists in parallel.
func (v *view) sync(ctx context.Context) {
	v.mu.Lock()
	defer v.mu.Unlock()
	targets := map[string]*upstream{}
	v.g.mu.RLock()
	for name, u := range v.g.ups {
		if u.cfg.Enabled && (v.all || slices.Contains(v.names, name)) {
			targets[name] = u
		}
	}
	v.g.mu.RUnlock()

	type fetched struct {
		tools []*mcp.Tool
		gen   uint64
	}
	results := make(map[string]fetched, len(targets))
	var rmu sync.Mutex
	var wg sync.WaitGroup
	for name, u := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tools, _ := u.listTools(ctx, false)
			rmu.Lock()
			results[name] = fetched{tools, u.gen()}
			rmu.Unlock()
		}()
	}
	wg.Wait()

	for name, e := range v.reg {
		if u, ok := targets[name]; !ok || u != e.u {
			v.srv.RemoveTools(e.tools...)
			delete(v.reg, name)
		}
	}
	for name, u := range targets {
		f := results[name]
		e, have := v.reg[name]
		if have && e.gen == f.gen {
			continue
		}
		if f.tools == nil {
			continue // unreachable and never listed: nothing to register yet
		}
		if have {
			v.srv.RemoveTools(e.tools...)
		}
		ne := viewEntry{u: u, gen: f.gen}
		for _, t := range f.tools {
			if n, ok := v.addTool(u.cfg.Name, t); ok {
				ne.tools = append(ne.tools, n)
			}
		}
		v.reg[name] = ne
	}
}

func (v *view) addTool(server string, t *mcp.Tool) (name string, ok bool) {
	nt := *t
	nt.Name = server + NamespaceSep + t.Name
	nt.InputSchema = objectSchema(t.InputSchema)
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("mcp: skipping upstream tool", "server", server, "tool", t.Name, "err", r)
			ok = false
		}
	}()
	v.srv.AddTool(&nt, v.g.toolHandler(server, t.Name))
	return nt.Name, true
}

// objectSchema coerces an upstream input schema into a JSON object schema.
func objectSchema(s any) any {
	var m map[string]any
	if b, err := json.Marshal(s); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	if m == nil {
		return map[string]any{"type": "object"}
	}
	if typ, _ := m["type"].(string); typ != "object" {
		if _, has := m["type"]; has {
			return map[string]any{"type": "object"}
		}
		m["type"] = "object"
	}
	return m
}

// --- tool calls ---

var (
	errDenied        = errors.New("access to this MCP server is not allowed for this key")
	errUnknownServer = errors.New("unknown or disabled MCP server")
)

func (g *Gateway) toolHandler(server, tool string) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		p := principalFromExtra(req.Extra)
		var args any = map[string]any{}
		if raw := req.Params.Arguments; len(raw) > 0 && string(raw) != "null" {
			args = raw
		}
		res, err := g.call(ctx, p, true, server, tool, args)
		switch {
		case errors.Is(err, errDenied), errors.Is(err, errUnknownServer):
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: err.Error()}
		case err != nil:
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "upstream MCP server error: " + err.Error()}}}, nil
		}
		return res, nil
	}
}

// CallTool invokes a tool on an upstream server on behalf of the principal in ctx
// (if any). The caller is responsible for authorisation. Used by the console.
func (g *Gateway) CallTool(ctx context.Context, server, tool string, args map[string]any) (*mcp.CallToolResult, error) {
	if args == nil {
		args = map[string]any{}
	}
	return g.call(ctx, auth.FromContext(ctx), false, server, tool, args)
}

func (g *Gateway) call(ctx context.Context, p *auth.Principal, enforce bool, server, tool string, args any) (*mcp.CallToolResult, error) {
	start := time.Now()
	u := g.upstream(server)
	var err error
	var res *mcp.CallToolResult
	switch {
	case u == nil || !u.config().Enabled:
		err = errUnknownServer
	case enforce && !Allowed(p, u.config()):
		err = errDenied
	default:
		res, err = u.callTool(ctx, tool, args)
	}
	rec := callRecord{at: start, server: server, tool: tool, dur: time.Since(start), ok: err == nil && res != nil && !res.IsError}
	if p != nil {
		rec.keyID, rec.userID = p.KeyID(), p.UserID()
	}
	status := "ok"
	switch {
	case errors.Is(err, errDenied):
		status, rec.err = "denied", err.Error()
	case err != nil:
		status, rec.err = "error", err.Error()
	case !rec.ok:
		status, rec.err = "error", resultText(res)
	}
	if !errors.Is(err, errUnknownServer) {
		metrics.MCPCalls.WithLabelValues(server, status).Inc()
		g.logCall(rec)
	}
	return res, err
}

func (u *upstream) config() Server {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.cfg
}

// resultText joins the text content of a result (for error messages).
func resultText(res *mcp.CallToolResult) string {
	if res == nil {
		return ""
	}
	var parts []string
	for _, c := range res.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			parts = append(parts, t.Text)
		}
	}
	if len(parts) == 0 {
		return "tool returned an error"
	}
	return strings.Join(parts, "\n")
}

// --- console helpers ---

// ListServerTools returns a server's tools (cached unless refresh is set).
func (g *Gateway) ListServerTools(ctx context.Context, server string, refresh bool) ([]*mcp.Tool, error) {
	u := g.upstream(server)
	if u == nil {
		return nil, errUnknownServer
	}
	tools, err := u.listTools(ctx, refresh)
	if refresh && err == nil {
		go func() {
			sctx, cancel := context.WithTimeout(g.ctx, listTimeout)
			defer cancel()
			g.syncViews(sctx)
		}()
	}
	return tools, err
}

// Status reports the connection state of a server.
func (g *Gateway) Status(server string) Status {
	u := g.upstream(server)
	if u == nil {
		return Status{}
	}
	return u.status()
}

// TestConnection connects to an (unsaved) server definition and lists its tools.
func (g *Gateway) TestConnection(ctx context.Context, s Server) ([]*mcp.Tool, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()
	cs, stop, err := g.dial(ctx, s, nil)
	if err != nil {
		return nil, err
	}
	defer stop()
	defer cs.Close()
	tools, err := collectTools(ctx, cs)
	if err != nil {
		return nil, fmt.Errorf("list tools: %w", err)
	}
	return tools, nil
}

// --- async call log ---

type callRecord struct {
	at            time.Time
	server, tool  string
	keyID, userID string
	dur           time.Duration
	ok            bool
	err           string
}

func (g *Gateway) logCall(r callRecord) {
	if g.store == nil {
		return
	}
	if len(r.err) > 2000 {
		r.err = r.err[:2000] + "…"
	}
	select {
	case g.calls <- r:
	default:
		slog.Warn("mcp: call log queue full, dropping record", "server", r.server, "tool", r.tool)
	}
}

func (g *Gateway) logLoop() {
	defer close(g.logDone)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var buf []callRecord
	flush := func() {
		if len(buf) == 0 || g.store == nil {
			buf = buf[:0]
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		b := &pgxBatch{}
		for _, r := range buf {
			b.add(r)
		}
		if err := b.send(ctx, g.store); err != nil {
			slog.Error("mcp: write call log", "err", err, "records", len(buf))
		}
		buf = buf[:0]
	}
	for {
		select {
		case r := <-g.calls:
			buf = append(buf, r)
			if len(buf) >= 200 {
				flush()
			}
		case <-tick.C:
			flush()
		case <-g.ctx.Done():
			for {
				select {
				case r := <-g.calls:
					buf = append(buf, r)
				default:
					flush()
					return
				}
			}
		}
	}
}
