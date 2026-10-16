package api

import (
	"encoding/json"
	"net/http"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"lemongate/internal/alerting"
	"lemongate/internal/settings"
	"lemongate/internal/store"
)

type obj = map[string]any

// schemaTypes maps schema names to Go types; schemas are derived by reflection on
// their JSON tags so the document stays in sync with the API.
var schemaTypes = map[string]any{
	"Key":               store.Key{},
	"KeyInput":          keyInput{},
	"KeyCreated":        keyCreated{},
	"User":              store.User{},
	"UserInput":         userInput{},
	"Team":              store.Team{},
	"TeamMember":        store.TeamMember{},
	"MemberInput":       memberInput{},
	"Organization":      store.Organization{},
	"Deployment":        store.Deployment{},
	"Alias":             store.Alias{},
	"AccessGroup":       store.AccessGroup{},
	"Fallback":          store.Fallback{},
	"Credential":        store.Credential{},
	"CredentialInput":   credentialInput{},
	"Tag":               store.Tag{},
	"EndUser":           store.EndUser{},
	"BudgetPreset":      store.BudgetPreset{},
	"Settings":          settings.Settings{},
	"AuditEntry":        store.AuditEntry{},
	"Deleted":           deletedResp{},
	"AlertChannel":      channelOut{},
	"AlertChannelInput": channelInput{},
	"AlertHistoryEntry": alerting.HistoryEntry{},
	"UsageTotals":       usageTotals{},
	"DeploymentHealth":  depHealth{},

	"GuardrailPolicy":      policyOut{},
	"GuardrailPolicyInput": policyInput{},
	"GuardrailPreset":      presetOut{},
	"PresetInstallInput":   presetInstallInput{},
	"GuardrailCatalog":     catalogOut{},
}

var readOnlyFields = map[string]bool{"id": true, "created_at": true, "updated_at": true, "spend": true, "budget_reset_at": true,
	"key_hint": true, "member_count": true, "key_count": true, "team_count": true, "user_count": true, "usage_count": true,
	"last_used_at": true, "last_login_at": true, "deleted_at": true, "created_by": true, "user_email": true, "team_name": true,
	"org_name": true, "credential_name": true, "hint": true, "first_seen_at": true, "last_seen_at": true, "from_config": true}

var timeType = reflect.TypeOf(time.Time{})

func schemaFor(t reflect.Type) obj {
	nullable := false
	for t.Kind() == reflect.Pointer {
		t, nullable = t.Elem(), true
	}
	var s obj
	switch {
	case t == timeType:
		s = obj{"type": "string", "format": "date-time"}
	case t.Kind() == reflect.String:
		s = obj{"type": "string"}
	case t.Kind() == reflect.Bool:
		s = obj{"type": "boolean"}
	case t.Kind() >= reflect.Int && t.Kind() <= reflect.Uint64:
		s = obj{"type": "integer"}
	case t.Kind() == reflect.Float32 || t.Kind() == reflect.Float64:
		s = obj{"type": "number"}
	case t.Kind() == reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			s = obj{"type": "string"}
		} else {
			s = obj{"type": "array", "items": schemaFor(t.Elem())}
		}
	case t.Kind() == reflect.Map:
		s = obj{"type": "object", "additionalProperties": schemaFor(t.Elem())}
	case t.Kind() == reflect.Interface:
		s = obj{}
	case t.Kind() == reflect.Struct:
		props := obj{}
		collectProps(t, props)
		s = obj{"type": "object", "properties": props}
	default:
		s = obj{}
	}
	if nullable {
		if typ, ok := s["type"].(string); ok {
			s["type"] = []string{typ, "null"}
		}
	}
	return s
}

func collectProps(t reflect.Type, props obj) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "-" || (!f.IsExported() && !f.Anonymous) {
			continue
		}
		if f.Anonymous && name == "" {
			ft := f.Type
			for ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				collectProps(ft, props)
				continue
			}
		}
		if name == "" {
			name = f.Name
		}
		s := schemaFor(f.Type)
		if readOnlyFields[name] {
			s["readOnly"] = true
		}
		props[name] = s
	}
}

func rawSchema(t *rawTable) obj {
	props := obj{"id": obj{"type": "string", "readOnly": true}}
	var req []string
	for _, c := range t.Cols {
		var s obj
		switch c.Type {
		case "bool":
			s = obj{"type": "boolean"}
		case "float":
			s = obj{"type": "number"}
		case "json":
			s = obj{"type": "object"}
		case "uuid":
			s = obj{"type": []string{"string", "null"}}
		default:
			s = obj{"type": "string"}
		}
		if len(c.Enum) > 0 {
			s["enum"] = c.Enum
		}
		if c.Desc != "" {
			s["description"] = c.Desc
		}
		if c.Required {
			req = append(req, c.Name)
		}
		props[c.Name] = s
	}
	props["created_at"] = obj{"type": "string", "format": "date-time", "readOnly": true}
	props["updated_at"] = obj{"type": "string", "format": "date-time", "readOnly": true}
	return obj{"type": "object", "properties": props, "required": req}
}

func ref(name string) obj { return obj{"$ref": "#/components/schemas/" + name} }

func respSchema(name string) obj {
	if name == "" {
		return obj{"type": "object"}
	}
	if item, ok := strings.CutPrefix(name, "list:"); ok {
		return obj{"type": "object", "properties": obj{"data": obj{"type": "array", "items": ref(item)}, "count": obj{"type": "integer"}}}
	}
	return ref(name)
}

var pathParam = regexp.MustCompile(`\{([a-z_]+)\}`)

func opID(rt route) string {
	parts := []string{strings.ToLower(rt.Method)}
	for _, seg := range strings.Split(strings.Trim(rt.Path, "/"), "/") {
		seg = strings.Trim(seg, "{}")
		seg = strings.ReplaceAll(seg, "-", "_")
		parts = append(parts, seg)
	}
	return strings.Join(parts, "_")
}

func buildOpenAPI(table []route, baseURL string) obj {
	schemas := obj{
		"Error": obj{"type": "object", "properties": obj{"error": obj{"type": "object", "properties": obj{
			"message": obj{"type": "string"}, "type": obj{"type": "string",
				"enum": []string{"authentication_error", "permission_error", "invalid_request_error", "not_found", "conflict", "internal_error"}}}}}},
		"Principal": obj{"type": "object", "properties": obj{"kind": obj{"type": "string"}, "role": obj{"type": "string"},
			"label": obj{"type": "string"}, "read_only": obj{"type": "boolean"}, "user": ref("User"), "team": ref("Team"), "key": ref("Key"),
			"memberships": obj{"type": "array", "items": ref("TeamMember")}}},
		"Usage": obj{"type": "object", "properties": obj{"from": obj{"type": "string", "format": "date"}, "to": obj{"type": "string", "format": "date"},
			"group_by": obj{"type": "string"}, "totals": ref("UsageTotals"),
			"daily":     obj{"type": "array", "items": obj{"allOf": []any{ref("UsageTotals"), obj{"type": "object", "properties": obj{"day": obj{"type": "string", "format": "date"}}}}}},
			"breakdown": obj{"type": "array", "items": obj{"allOf": []any{ref("UsageTotals"), obj{"type": "object", "properties": obj{"key": obj{"type": "string"}, "label": obj{"type": "string"}}}}}}}},
		"LogEntry": obj{"type": "object", "description": "One request_logs row.", "additionalProperties": true, "properties": obj{
			"id": obj{"type": "string"}, "request_id": obj{"type": "string"}, "created_at": obj{"type": "string", "format": "date-time"},
			"route": obj{"type": "string"}, "model": obj{"type": "string"}, "model_group": obj{"type": "string"}, "status": obj{"type": "string"},
			"http_status": obj{"type": "integer"}, "prompt_tokens": obj{"type": "integer"}, "completion_tokens": obj{"type": "integer"},
			"cost": obj{"type": "number"}, "latency_ms": obj{"type": "integer"}, "error": obj{"type": "string"}}},
		"LogPage": obj{"type": "object", "properties": obj{"data": obj{"type": "array", "items": ref("LogEntry")}, "count": obj{"type": "integer"},
			"next_cursor": obj{"type": []string{"string", "null"}}}},
		"TestResult": obj{"type": "object", "properties": obj{"ok": obj{"type": "boolean"}, "error": obj{"type": "object", "properties": obj{
			"message": obj{"type": "string"}, "type": obj{"type": "string"}}}}},
		"Health": obj{"type": "object", "properties": obj{"deployments": obj{"type": "array", "items": ref("DeploymentHealth")},
			"count": obj{"type": "integer"}, "summary": obj{"type": "object", "additionalProperties": obj{"type": "integer"}}}},
	}
	for name, v := range schemaTypes {
		schemas[name] = schemaFor(reflect.TypeOf(v))
	}
	for i := range rawTables {
		schemas[rawTables[i].Schema] = rawSchema(&rawTables[i])
	}
	errResp := func(desc string) obj {
		return obj{"description": desc, "content": obj{"application/json": obj{"schema": ref("Error")}}}
	}
	paths := obj{}
	for _, rt := range table {
		p := "/api/v1" + rt.Path
		item, _ := paths[p].(obj)
		if item == nil {
			item = obj{}
			paths[p] = item
		}
		var params []any
		for _, m := range pathParam.FindAllStringSubmatch(rt.Path, -1) {
			params = append(params, obj{"name": m[1], "in": "path", "required": true, "schema": obj{"type": "string"}})
		}
		for _, q := range rt.Query {
			typ, format := q.Type, ""
			if typ == "date" {
				typ, format = "string", "date"
			}
			sch := obj{"type": typ}
			if format != "" {
				sch["format"] = format
			}
			params = append(params, obj{"name": q.Name, "in": "query", "required": false, "description": q.Desc, "schema": sch})
		}
		status := rt.Status
		if status == 0 {
			status = http.StatusOK
		}
		op := obj{
			"operationId": opID(rt), "summary": rt.Summary, "tags": []string{rt.Tag},
			"responses": obj{
				strconv.Itoa(status): obj{"description": http.StatusText(status), "content": obj{"application/json": obj{"schema": respSchema(rt.Resp)}}},
				"400":                errResp("Invalid request"),
				"401":                errResp("Missing or invalid API key"),
				"403":                errResp("Not permitted (inference-scope key, read-only role, or missing admin role)"),
			},
		}
		desc := rt.Desc
		switch rt.Access {
		case accessAdmin:
			desc = strings.TrimSpace(desc + "\n\nRequires the admin role.")
		case accessViewer:
			if rt.Method == http.MethodGet {
				desc = strings.TrimSpace(desc + "\n\nRequires the admin or admin viewer role.")
			} else {
				desc = strings.TrimSpace(desc + "\n\nRequires the admin role.")
			}
		}
		if desc != "" {
			op["description"] = desc
		}
		if strings.Contains(rt.Path, "{") {
			op["responses"].(obj)["404"] = errResp("Not found")
		}
		if len(params) > 0 {
			op["parameters"] = params
		}
		if rt.Body != "" {
			content := obj{"schema": ref(rt.Body)}
			if rt.Example != "" {
				content["example"] = jsonExample(rt.Example)
			}
			op["requestBody"] = obj{"required": true, "content": obj{"application/json": content}}
		}
		item[strings.ToLower(rt.Method)] = op
	}
	var tags []any
	for _, t := range tagInfo {
		tags = append(tags, obj{"name": t.Name, "description": t.Desc})
	}
	servers := []any{obj{"url": strings.TrimRight(baseURL, "/")}}
	return obj{
		"openapi": "3.1.0",
		"info": obj{"title": "LemonGate Management API", "version": "1.0.0",
			"description": "Manage keys, users, teams, models, budgets and settings, and read usage, logs and health. " +
				"Authenticate with `Authorization: Bearer <key>` using the master key or a virtual key with `admin` or `management` scope."},
		"servers":    servers,
		"security":   []any{obj{"bearerAuth": []string{}}},
		"tags":       tags,
		"paths":      paths,
		"components": obj{"schemas": schemas, "securitySchemes": obj{"bearerAuth": obj{"type": "http", "scheme": "bearer", "description": "Master key or a management/admin-scope virtual key"}}},
	}
}

func jsonExample(s string) any {
	var v any
	if json.Unmarshal([]byte(s), &v) != nil {
		return s
	}
	return v
}

// sortedTags returns route tags in reference order.
func sortedTags(table []route) []string {
	order := map[string]int{}
	for i, t := range tagInfo {
		order[t.Name] = i
	}
	seen := map[string]bool{}
	var out []string
	for _, rt := range table {
		if !seen[rt.Tag] {
			seen[rt.Tag] = true
			out = append(out, rt.Tag)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return order[out[i]] < order[out[j]] })
	return out
}
