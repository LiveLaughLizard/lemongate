package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"lemongate/internal/guardrails"
	"lemongate/internal/store"
)

// rawTable describes a table managed by an optional module (guardrails, MCP gateway,
// pass-through). The API edits rows directly and then asks the module to reload.
type rawTable struct {
	Name     string // SQL table
	Path     string // URL segment
	Entity   string // audit entity type
	Label    string // human singular
	Tag      string
	Schema   string
	Cols     []rawCol
	Reload   string // hook name
	Example  string
	pickHook func(*Hooks) func(context.Context) error
}

type rawCol struct {
	Name     string
	Type     string // text | bool | float | int | json | uuid
	Required bool
	Enum     []string
	Desc     string
}

var rawTables = []rawTable{
	{Name: "guardrails", Path: "guardrails", Entity: "guardrail", Label: "guardrail", Tag: "Extensions", Schema: "Guardrail", Reload: "guardrails",
		pickHook: func(h *Hooks) func(context.Context) error { return h.ReloadGuardrails },
		Example:  `{"name": "no-pii", "kind": "pii", "mode": "pre", "action": "mask", "default_on": true}`,
		Cols: []rawCol{
			{Name: "name", Type: "text", Required: true},
			{Name: "kind", Type: "text", Required: true, Enum: guardrails.Kinds},
			{Name: "mode", Type: "text", Enum: []string{"pre", "post", "both"}},
			{Name: "action", Type: "text", Enum: []string{"block", "mask", "log"}},
			{Name: "config", Type: "json", Desc: "Kind-specific configuration"},
			{Name: "default_on", Type: "bool", Desc: "Apply to every request unless overridden"},
			{Name: "enabled", Type: "bool"},
			{Name: "description", Type: "text"},
			{Name: "preset", Type: "text", Desc: "Id of the preset that created the guardrail (provenance; empty for hand-made guardrails)"},
		}},
	{Name: "mcp_servers", Path: "mcp-servers", Entity: "mcp_server", Label: "MCP server", Tag: "Extensions", Schema: "MCPServer", Reload: "mcp",
		pickHook: func(h *Hooks) func(context.Context) error { return h.ReloadMCP },
		Example:  `{"name": "github", "url": "http://mcp-github:8080/mcp", "transport": "http", "available_to_all": true}`,
		Cols: []rawCol{
			{Name: "name", Type: "text", Required: true},
			{Name: "url", Type: "text", Required: true},
			{Name: "transport", Type: "text", Enum: []string{"http", "sse"}},
			{Name: "credential_id", Type: "uuid", Desc: "Credential injected as the auth header"},
			{Name: "auth_header", Type: "text"},
			{Name: "auth_prefix", Type: "text"},
			{Name: "description", Type: "text"},
			{Name: "available_to_all", Type: "bool"},
			{Name: "enabled", Type: "bool"},
		}},
	{Name: "passthrough_routes", Path: "passthrough-routes", Entity: "passthrough_route", Label: "pass-through route", Tag: "Extensions", Schema: "PassthroughRoute", Reload: "passthrough",
		pickHook: func(h *Hooks) func(context.Context) error { return h.ReloadPassthrough },
		Example:  `{"name": "vllm-metrics", "target_url": "http://vllm-1:8000/metrics", "require_key": true}`,
		Cols: []rawCol{
			{Name: "name", Type: "text", Required: true},
			{Name: "target_url", Type: "text", Required: true},
			{Name: "credential_id", Type: "uuid"},
			{Name: "auth_header", Type: "text"},
			{Name: "auth_prefix", Type: "text"},
			{Name: "extra_headers", Type: "json", Desc: "Headers added to upstream requests"},
			{Name: "require_key", Type: "bool"},
			{Name: "cost_per_request", Type: "float"},
			{Name: "description", Type: "text"},
			{Name: "enabled", Type: "bool"},
		}},
}

func (h *H) rawRoutes() []route {
	var out []route
	for i := range rawTables {
		t := &rawTables[i]
		base := "/" + t.Path
		out = append(out,
			route{Method: "GET", Path: base, Tag: t.Tag, Summary: "List " + t.Label + "s", Access: accessViewer, Resp: "list:" + t.Schema, handler: h.rawList(t)},
			route{Method: "POST", Path: base, Tag: t.Tag, Summary: "Create " + t.Label, Access: accessViewer, Body: t.Schema, Resp: t.Schema, Status: 201, Example: t.Example, handler: h.rawCreate(t)},
			route{Method: "GET", Path: base + "/{id}", Tag: t.Tag, Summary: "Get " + t.Label, Desc: "`{id}` accepts the id or the unique name.", Access: accessViewer, Resp: t.Schema, handler: h.rawGet(t)},
			route{Method: "PATCH", Path: base + "/{id}", Tag: t.Tag, Summary: "Update " + t.Label, Access: accessViewer, Body: t.Schema, Resp: t.Schema, handler: h.rawUpdate(t)},
			route{Method: "DELETE", Path: base + "/{id}", Tag: t.Tag, Summary: "Delete " + t.Label, Access: accessViewer, Resp: "Deleted", handler: h.rawDelete(t)},
		)
	}
	return out
}

func (t *rawTable) selectCols() string {
	cols := []string{"id::text AS id"}
	for _, c := range t.Cols {
		if c.Type == "uuid" {
			cols = append(cols, c.Name+"::text AS "+c.Name)
		} else {
			cols = append(cols, c.Name)
		}
	}
	return strings.Join(append(cols, "created_at", "updated_at"), ", ")
}

func (t *rawTable) col(name string) (rawCol, bool) {
	for _, c := range t.Cols {
		if c.Name == name {
			return c, true
		}
	}
	return rawCol{}, false
}

// coerce validates one JSON value for a column and returns the SQL argument.
func (c rawCol) coerce(raw json.RawMessage) (any, error) {
	isNull := string(raw) == "null"
	switch c.Type {
	case "text":
		var s string
		if isNull || json.Unmarshal(raw, &s) != nil {
			return nil, fmt.Errorf("%s must be a string", c.Name)
		}
		s = strings.TrimSpace(s)
		if c.Required && s == "" {
			return nil, fmt.Errorf("%s is required", c.Name)
		}
		if len(c.Enum) > 0 && !slices.Contains(c.Enum, s) {
			return nil, fmt.Errorf("%s must be one of %s", c.Name, strings.Join(c.Enum, ", "))
		}
		return s, nil
	case "bool":
		var b bool
		if isNull || json.Unmarshal(raw, &b) != nil {
			return nil, fmt.Errorf("%s must be a boolean", c.Name)
		}
		return b, nil
	case "float":
		var f float64
		if isNull || json.Unmarshal(raw, &f) != nil || f < 0 {
			return nil, fmt.Errorf("%s must be a non-negative number", c.Name)
		}
		return f, nil
	case "json":
		var m map[string]any
		if isNull {
			return map[string]any{}, nil
		}
		if json.Unmarshal(raw, &m) != nil {
			return nil, fmt.Errorf("%s must be a JSON object", c.Name)
		}
		return m, nil
	case "uuid":
		if isNull {
			return nil, nil
		}
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return nil, fmt.Errorf("%s must be a string id or null", c.Name)
		}
		if s == "" {
			return nil, nil
		}
		return s, nil
	}
	return nil, fmt.Errorf("unsupported column %s", c.Name)
}

// bindRaw turns a JSON object into column → argument pairs (in table order).
func (t *rawTable) bind(body map[string]json.RawMessage, create bool) ([]string, []any, error) {
	for k := range body {
		if _, ok := t.col(k); !ok && k != "id" && k != "created_at" && k != "updated_at" {
			return nil, nil, fmt.Errorf("unknown field %q", k)
		}
	}
	var names []string
	var args []any
	for _, c := range t.Cols {
		raw, ok := body[c.Name]
		if !ok {
			if create && c.Required {
				return nil, nil, fmt.Errorf("%s is required", c.Name)
			}
			continue
		}
		v, err := c.coerce(raw)
		if err != nil {
			return nil, nil, err
		}
		names = append(names, c.Name)
		args = append(args, v)
	}
	return names, args, nil
}

func (h *H) rawFetch(ctx context.Context, t *rawTable, idOrName string) (map[string]any, error) {
	rows, err := h.d.Store.Pool.Query(ctx, `SELECT `+t.selectCols()+` FROM `+t.Name+` WHERE id::text = $1 OR name = $1 LIMIT 1`, idOrName)
	if err != nil {
		return nil, err
	}
	m, err := pgx.CollectExactlyOneRow(rows, pgx.RowToMap)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return m, err
}

func (h *H) rawList(t *rawTable) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := h.d.Store.Pool.Query(r.Context(), `SELECT `+t.selectCols()+` FROM `+t.Name+` ORDER BY name`)
		if err != nil {
			storeErr(w, err, t.Label+"s")
			return
		}
		items, err := pgx.CollectRows(rows, pgx.RowToMap)
		if err != nil {
			storeErr(w, err, t.Label+"s")
			return
		}
		writeJSON(w, 200, list(items))
	}
}

func (h *H) rawGet(t *rawTable) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m, err := h.rawFetch(r.Context(), t, param(r, "id"))
		if err != nil {
			storeErr(w, err, t.Label)
			return
		}
		writeJSON(w, 200, m)
	}
}

func (h *H) rawBody(w http.ResponseWriter, r *http.Request) (map[string]json.RawMessage, bool) {
	var body map[string]json.RawMessage
	if !decode(w, r, &body) {
		return nil, false
	}
	if body == nil {
		badRequest(w, "request body must be a JSON object")
		return nil, false
	}
	return body, true
}

func placeholderFor(c rawCol, i int) string {
	if c.Type == "uuid" {
		return fmt.Sprintf("$%d::uuid", i)
	}
	return fmt.Sprintf("$%d", i)
}

func (h *H) rawCreate(t *rawTable) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := h.rawBody(w, r)
		if !ok {
			return
		}
		names, args, err := t.bind(body, true)
		if err != nil {
			badRequest(w, "%s", err.Error())
			return
		}
		ph := make([]string, len(names))
		for i, n := range names {
			c, _ := t.col(n)
			ph[i] = placeholderFor(c, i+1)
		}
		var id string
		err = h.d.Store.Pool.QueryRow(r.Context(), `INSERT INTO `+t.Name+` (`+strings.Join(names, ", ")+`) VALUES (`+strings.Join(ph, ", ")+`) RETURNING id::text`, args...).Scan(&id)
		if err != nil {
			storeErr(w, dbErr(err), t.Label)
			return
		}
		m, _ := h.rawFetch(r.Context(), t, id)
		runHook(r.Context(), t.Reload, t.pickHook)
		h.d.Audit(r, "create", t.Entity, id, fmt.Sprintf("Created %s %v via API", t.Label, m["name"]), nil, m)
		writeJSON(w, 201, m)
	}
}

func (h *H) rawUpdate(t *rawTable) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		before, err := h.rawFetch(r.Context(), t, param(r, "id"))
		if err != nil {
			storeErr(w, err, t.Label)
			return
		}
		body, ok := h.rawBody(w, r)
		if !ok {
			return
		}
		names, args, err := t.bind(body, false)
		if err != nil {
			badRequest(w, "%s", err.Error())
			return
		}
		id := before["id"].(string)
		if len(names) > 0 {
			sets := make([]string, len(names))
			for i, n := range names {
				c, _ := t.col(n)
				sets[i] = n + " = " + placeholderFor(c, i+2)
			}
			_, err = h.d.Store.Pool.Exec(r.Context(), `UPDATE `+t.Name+` SET `+strings.Join(sets, ", ")+`, updated_at = now() WHERE id = $1`, append([]any{id}, args...)...)
			if err != nil {
				storeErr(w, dbErr(err), t.Label)
				return
			}
		}
		m, _ := h.rawFetch(r.Context(), t, id)
		runHook(r.Context(), t.Reload, t.pickHook)
		h.d.Audit(r, "update", t.Entity, id, fmt.Sprintf("Updated %s %v via API", t.Label, m["name"]), before, m)
		writeJSON(w, 200, m)
	}
}

func (h *H) rawDelete(t *rawTable) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		before, err := h.rawFetch(r.Context(), t, param(r, "id"))
		if err != nil {
			storeErr(w, err, t.Label)
			return
		}
		id := before["id"].(string)
		if _, err := h.d.Store.Pool.Exec(r.Context(), `DELETE FROM `+t.Name+` WHERE id = $1`, id); err != nil {
			storeErr(w, dbErr(err), t.Label)
			return
		}
		runHook(r.Context(), t.Reload, t.pickHook)
		h.d.Audit(r, "delete", t.Entity, id, fmt.Sprintf("Deleted %s %v via API", t.Label, before["name"]), before, nil)
		writeJSON(w, 200, deleted(id))
	}
}
