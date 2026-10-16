// Package mcpui is the MCP servers console area: register upstream MCP servers,
// browse and run their tools, inspect the tool call log and connect clients.
package mcpui

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"lemongate/internal/auth"
	"lemongate/internal/mcpgw"
	"lemongate/internal/store"
	"lemongate/internal/ui"
)

const area = "mcp"

type H struct {
	d *ui.Deps
	g *mcpgw.Gateway
}

// Mount registers routes for this area on the session-protected router.
func Mount(r chi.Router, d *ui.Deps, g *mcpgw.Gateway) {
	h := &H{d: d, g: g}
	r.Get("/ui/mcp", h.index)
	r.Get("/ui/mcp/servers", h.servers)
	r.Get("/ui/mcp/calls", h.calls)
	r.Get("/ui/mcp/{id}", h.show)
	r.Get("/ui/mcp/{id}/tools", h.tools)
	r.Get("/ui/mcp/{id}/run", h.runForm)
	r.Post("/ui/mcp/{id}/run", h.run)
	r.Group(func(r chi.Router) {
		r.Use(ui.RequireAdmin)
		r.Get("/ui/mcp/new", h.newForm)
		r.Post("/ui/mcp", h.create)
		r.Post("/ui/mcp/test", h.test)
		r.Get("/ui/mcp/{id}/edit", h.editForm)
		r.Post("/ui/mcp/{id}", h.update)
		r.Post("/ui/mcp/{id}/toggle", h.toggle)
		r.Post("/ui/mcp/{id}/delete", h.delete)
	})
}

// --- access ---

// access describes which servers a console user may see.
type access struct {
	all   bool
	names map[string]bool
}

func (a access) can(s mcpgw.Server) bool {
	return a.all || a.names[s.Name] || (s.AvailableToAll && s.Enabled)
}

// accessFor: admins and read-only admins see everything; members see servers that
// are available to all, or granted to one of their teams or their own keys.
func (h *H) accessFor(ctx context.Context, p *auth.Principal) access {
	if p.CanViewAll() {
		return access{all: true}
	}
	a := access{names: map[string]bool{}}
	uid := p.UserID()
	if uid == "" {
		return a
	}
	if teams, err := h.d.Store.TeamsForUser(ctx, uid); err == nil {
		for _, t := range teams {
			for _, n := range t.MCPServers {
				a.names[n] = true
			}
		}
	}
	if keys, err := h.d.Store.ListKeys(ctx, store.KeyFilter{UserID: uid}); err == nil {
		for _, k := range keys {
			for _, n := range k.MCPServers {
				a.names[n] = true
			}
		}
	}
	return a
}

func (h *H) visible(ctx context.Context, p *auth.Principal) ([]mcpgw.Server, access, error) {
	a := h.accessFor(ctx, p)
	all, err := h.g.ListServers(ctx)
	if err != nil {
		return nil, a, err
	}
	out := all[:0]
	for _, s := range all {
		if a.can(s) && (a.all || s.Enabled) {
			out = append(out, s)
		}
	}
	return out, a, nil
}

// load fetches the server in the URL and checks the caller may see it.
func (h *H) load(w http.ResponseWriter, r *http.Request) (mcpgw.Server, *auth.Principal, bool) {
	p := auth.FromContext(r.Context())
	s, err := h.g.GetServer(r.Context(), chi.URLParam(r, "id"))
	if err == nil && !h.accessFor(r.Context(), p).can(s) {
		err = mcpgw.ErrNotFound
	}
	if err != nil {
		if ui.IsHTMX(r) {
			ui.Fail(w, http.StatusNotFound, "MCP server not found")
		} else {
			http.NotFound(w, r)
		}
		return s, p, false
	}
	return s, p, true
}

// --- index ---

type indexData struct {
	IsAdmin  bool
	Endpoint string
	Servers  []mcpgw.Server
	Config   string
}

func (h *H) index(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	servers, _, _ := h.visible(r.Context(), p)
	endpoint := strings.TrimRight(h.d.Cfg.BaseURL, "/") + "/mcp"
	h.d.Render(w, r, "mcp/index", "mcp", "MCP servers", indexData{
		IsAdmin: p.IsAdmin(), Endpoint: endpoint, Servers: servers, Config: clientConfig(endpoint),
	})
}

func clientConfig(endpoint string) string {
	return `{
  "mcpServers": {
    "lemongate": {
      "type": "http",
      "url": "` + endpoint + `",
      "headers": {
        "Authorization": "Bearer YOUR_LEMONGATE_API_KEY"
      }
    }
  }
}`
}

type serverCard struct {
	Server mcpgw.Server
	Status mcpgw.Status
	Stats  mcpgw.CallStats
}

type serversData struct {
	Cards   []serverCard
	IsAdmin bool
	Totals  mcpgw.CallStats
	Tools   int
	Online  int
}

func (h *H) servers(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	list, _, err := h.visible(r.Context(), p)
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	stats, _ := h.g.Stats(r.Context(), time.Now().Add(-24*time.Hour))
	sd := serversData{IsAdmin: p.IsAdmin() && !p.ReadOnly()}
	for _, s := range list {
		c := serverCard{Server: s, Status: h.g.Status(s.Name), Stats: stats[s.Name]}
		sd.Cards = append(sd.Cards, c)
		sd.Totals.Calls += c.Stats.Calls
		sd.Totals.Errors += c.Stats.Errors
		sd.Tools += c.Status.ToolCount
		if c.Status.State() == "ok" {
			sd.Online++
		}
	}
	h.d.Partial(w, r, 200, area, "mcp-servers", sd)
}

// --- create / edit ---

type formData struct {
	Server      mcpgw.Server
	IsNew       bool
	Error       string
	Credentials []store.Credential
}

func (h *H) form(ctx context.Context, s mcpgw.Server, isNew bool, msg string) formData {
	creds, _ := h.d.Store.ListCredentials(ctx)
	return formData{Server: s, IsNew: isNew, Error: msg, Credentials: creds}
}

func (h *H) newForm(w http.ResponseWriter, r *http.Request) {
	s := mcpgw.Server{Transport: mcpgw.TransportHTTP, AuthHeader: "Authorization", AuthPrefix: "Bearer ", Enabled: true}
	h.d.Partial(w, r, 200, area, "mcp-form", h.form(r.Context(), s, true, ""))
}

func bind(r *http.Request, s *mcpgw.Server) {
	_ = r.ParseForm()
	s.Name = strings.ToLower(ui.FormStr(r, "name"))
	s.URL = ui.FormStr(r, "url")
	s.Transport = ui.FormStr(r, "transport")
	s.CredentialID = store.NullIfEmpty(ui.FormStr(r, "credential_id"))
	s.AuthHeader = ui.FormStr(r, "auth_header")
	s.AuthPrefix = r.FormValue("auth_prefix") // keep trailing space ("Bearer ")
	s.Description = ui.FormStr(r, "description")
	s.AvailableToAll = ui.FormBool(r, "available_to_all")
	s.Enabled = ui.FormBool(r, "enabled")
}

func errMsg(err error) string {
	if errors.Is(err, mcpgw.ErrConflict) {
		return "A server with this name already exists."
	}
	return err.Error()
}

func (h *H) create(w http.ResponseWriter, r *http.Request) {
	var s mcpgw.Server
	bind(r, &s)
	created, err := h.g.CreateServer(r.Context(), s)
	if err != nil {
		h.d.Partial(w, r, 422, area, "mcp-form", h.form(r.Context(), s, true, errMsg(err)))
		return
	}
	h.d.Audit(r, "create", "mcp_server", created.ID, "Created MCP server "+created.Name, nil, created)
	ui.Done(w, "MCP server "+created.Name+" added", "refresh-mcp")
}

func (h *H) editForm(w http.ResponseWriter, r *http.Request) {
	s, _, ok := h.load(w, r)
	if !ok {
		return
	}
	h.d.Partial(w, r, 200, area, "mcp-form", h.form(r.Context(), s, false, ""))
}

func (h *H) update(w http.ResponseWriter, r *http.Request) {
	before, _, ok := h.load(w, r)
	if !ok {
		return
	}
	s := before
	bind(r, &s)
	if err := h.g.UpdateServer(r.Context(), s); err != nil {
		h.d.Partial(w, r, 422, area, "mcp-form", h.form(r.Context(), s, false, errMsg(err)))
		return
	}
	if before.Name != s.Name {
		h.d.Changed() // key/team allow-lists were rewritten
	}
	h.d.Audit(r, "update", "mcp_server", s.ID, "Updated MCP server "+s.Name, before, s)
	ui.Done(w, "MCP server saved", "refresh-mcp", "refresh-mcp-server")
}

func (h *H) toggle(w http.ResponseWriter, r *http.Request) {
	s, _, ok := h.load(w, r)
	if !ok {
		return
	}
	if err := h.g.SetEnabled(r.Context(), s.ID, !s.Enabled); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	verb := map[bool]string{true: "Enabled", false: "Disabled"}[!s.Enabled]
	h.d.Audit(r, strings.ToLower(verb[:len(verb)-1]), "mcp_server", s.ID, verb+" MCP server "+s.Name, nil, nil)
	ui.Done(w, verb+" "+s.Name, "refresh-mcp", "refresh-mcp-server")
}

func (h *H) delete(w http.ResponseWriter, r *http.Request) {
	s, _, ok := h.load(w, r)
	if !ok {
		return
	}
	if err := h.g.DeleteServer(r.Context(), s.ID); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Changed()
	h.d.Audit(r, "delete", "mcp_server", s.ID, "Deleted MCP server "+s.Name, s, nil)
	if r.URL.Query().Get("from") == "detail" {
		ui.Toast(w, "success", "MCP server deleted")
		ui.Redirect(w, r, "/ui/mcp")
		return
	}
	ui.Done(w, "MCP server deleted", "refresh-mcp")
}

type testData struct {
	Tools []*mcp.Tool
	Error string
	MS    int64
}

// test connects to the server described by the form (saved or not) and lists its tools.
func (h *H) test(w http.ResponseWriter, r *http.Request) {
	var s mcpgw.Server
	bind(r, &s)
	if s.Name == "" {
		s.Name = "test"
	}
	start := time.Now()
	tools, err := h.g.TestConnection(r.Context(), s)
	td := testData{Tools: tools, MS: time.Since(start).Milliseconds()}
	if err != nil {
		td.Error = err.Error()
	}
	h.d.Partial(w, r, 200, area, "mcp-test-result", td)
}

// --- detail ---

type showData struct {
	Server   mcpgw.Server
	Status   mcpgw.Status
	Stats    mcpgw.CallStats
	CanEdit  bool
	CanRun   bool
	Endpoint string
	ToolOpts []string
}

func (h *H) show(w http.ResponseWriter, r *http.Request) {
	s, p, ok := h.load(w, r)
	if !ok {
		return
	}
	sd := showData{Server: s, Status: h.g.Status(s.Name), CanEdit: p.IsAdmin() && !p.ReadOnly(), CanRun: !p.ReadOnly() && s.Enabled,
		Endpoint: strings.TrimRight(h.d.Cfg.BaseURL, "/") + "/mcp"}
	if stats, err := h.g.Stats(r.Context(), time.Now().Add(-24*time.Hour)); err == nil {
		sd.Stats = stats[s.Name]
	}
	sd.ToolOpts = h.g.ToolNames(r.Context(), s.Name)
	if r.Header.Get("HX-Target") == "mcp-server" {
		h.d.Partial(w, r, 200, area, "mcp-server-head", sd)
		return
	}
	h.d.Render(w, r, "mcp/show", "mcp", s.Name, sd, ui.Crumb{Label: "MCP servers", Href: "/ui/mcp"})
}

type toolView struct {
	Name        string // upstream tool name
	Gateway     string // namespaced name
	Title       string
	Description string
	Schema      any
	Output      any
	Params      []param
	ReadOnly    bool
	Destructive bool
}

type toolsData struct {
	Server mcpgw.Server
	Tools  []toolView
	Error  string
	CanRun bool
	Status mcpgw.Status
}

func toView(server string, t *mcp.Tool) toolView {
	tv := toolView{Name: t.Name, Gateway: server + mcpgw.NamespaceSep + t.Name, Title: t.Title, Description: t.Description,
		Schema: t.InputSchema, Output: t.OutputSchema}
	tv.Params, _ = schemaParams(t.InputSchema)
	if a := t.Annotations; a != nil {
		tv.ReadOnly = a.ReadOnlyHint
		tv.Destructive = a.DestructiveHint != nil && *a.DestructiveHint
		if tv.Title == "" {
			tv.Title = a.Title
		}
	}
	return tv
}

func (h *H) tools(w http.ResponseWriter, r *http.Request) {
	s, p, ok := h.load(w, r)
	if !ok {
		return
	}
	td := toolsData{Server: s, CanRun: !p.ReadOnly() && s.Enabled}
	if !s.Enabled {
		td.Error = "This server is disabled. Enable it to browse and run its tools."
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		tools, err := h.g.ListServerTools(ctx, s.Name, r.URL.Query().Get("refresh") == "1")
		if err != nil {
			td.Error = err.Error()
		}
		for _, t := range tools {
			td.Tools = append(td.Tools, toView(s.Name, t))
		}
		sort.Slice(td.Tools, func(i, j int) bool { return td.Tools[i].Name < td.Tools[j].Name })
	}
	td.Status = h.g.Status(s.Name)
	if r.URL.Query().Get("refresh") == "1" {
		if td.Error == "" {
			ui.Toast(w, "success", "Tool list refreshed")
		}
		ui.Refresh(w, "refresh-mcp-server")
	}
	h.d.Partial(w, r, 200, area, "mcp-tools", td)
}

// --- calls ---

type callsData struct {
	Calls   []mcpgw.Call
	Server  string
	Compact bool
}

func (h *H) calls(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	q := r.URL.Query()
	f := mcpgw.CallFilter{Server: q.Get("server"), Tool: q.Get("tool"), Status: q.Get("status"), Limit: 100}
	switch q.Get("range") {
	case "1h":
		f.Since = time.Now().Add(-time.Hour)
	case "7d":
		f.Since = time.Now().Add(-7 * 24 * time.Hour)
	case "30d":
		f.Since = time.Now().Add(-30 * 24 * time.Hour)
	default:
		f.Since = time.Now().Add(-24 * time.Hour)
	}
	if !p.CanViewAll() {
		// Members see their own calls on servers they can access.
		f.UserID = p.UserID()
		if f.UserID == "" {
			f.UserID = "00000000-0000-0000-0000-000000000000"
		}
		servers, _, _ := h.visible(r.Context(), p)
		f.Servers = []string{}
		for _, s := range servers {
			f.Servers = append(f.Servers, s.Name)
		}
	}
	calls, err := h.g.ListCalls(r.Context(), f)
	if err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Partial(w, r, 200, area, "mcp-calls", callsData{Calls: calls, Server: f.Server, Compact: q.Get("compact") == "1"})
}

// --- tool runner ---

type runData struct {
	Server mcpgw.Server
	Tool   toolView
	Raw    bool
	Values map[string]string
	Args   string
	Error  string
}

func (h *H) findTool(ctx context.Context, server, name string) (*mcp.Tool, error) {
	tools, err := h.g.ListServerTools(ctx, server, false)
	if err != nil && tools == nil {
		return nil, err
	}
	i := slices.IndexFunc(tools, func(t *mcp.Tool) bool { return t.Name == name })
	if i < 0 {
		return nil, errors.New("tool " + name + " not found on " + server)
	}
	return tools[i], nil
}

func (h *H) runForm(w http.ResponseWriter, r *http.Request) {
	s, p, ok := h.load(w, r)
	if !ok {
		return
	}
	if p.ReadOnly() || !s.Enabled {
		ui.Forbidden(w, r)
		return
	}
	t, err := h.findTool(r.Context(), s.Name, r.URL.Query().Get("tool"))
	if err != nil {
		ui.Fail(w, 404, err.Error())
		return
	}
	tv := toView(s.Name, t)
	_, simple := schemaParams(t.InputSchema)
	h.d.Partial(w, r, 200, area, "mcp-run-form", runData{Server: s, Tool: tv, Raw: !simple, Values: defaults(tv.Params), Args: exampleArgs(tv.Params)})
}

type resultPart struct {
	Kind string // text | image | json
	Text string
	Src  any // template.URL for images
	MIME string
}

type resultData struct {
	Error      string
	IsError    bool
	Parts      []resultPart
	Structured any
	MS         int64
	Tool       string
}

func (h *H) run(w http.ResponseWriter, r *http.Request) {
	s, p, ok := h.load(w, r)
	if !ok {
		return
	}
	if p.ReadOnly() || !s.Enabled {
		ui.Forbidden(w, r)
		return
	}
	_ = r.ParseForm()
	name := ui.FormStr(r, "tool")
	t, err := h.findTool(r.Context(), s.Name, name)
	if err != nil {
		h.d.Partial(w, r, 200, area, "mcp-run-result", resultData{Error: err.Error(), Tool: name})
		return
	}
	var args map[string]any
	if ui.FormBool(r, "raw") {
		args, err = ui.FormJSONMap(r, "args")
		if err != nil {
			err = errors.New("arguments must be a JSON object")
		}
	} else {
		params, _ := schemaParams(t.InputSchema)
		args, err = parseArgs(r, params)
	}
	if err != nil {
		h.d.Partial(w, r, 200, area, "mcp-run-result", resultData{Error: err.Error(), Tool: name})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	start := time.Now()
	res, err := h.g.CallTool(ctx, s.Name, name, args)
	rd := resultData{MS: time.Since(start).Milliseconds(), Tool: name}
	if err != nil {
		rd.Error = err.Error()
	} else {
		rd.IsError, rd.Parts, rd.Structured = res.IsError, resultParts(res), res.StructuredContent
	}
	ui.Refresh(w, "refresh-mcp-calls")
	h.d.Partial(w, r, 200, area, "mcp-run-result", rd)
}
