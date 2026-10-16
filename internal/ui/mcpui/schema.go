package mcpui

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// param is one top-level input property rendered as a form field.
type param struct {
	Name        string
	Type        string // string | number | integer | boolean | enum | json
	Description string
	Required    bool
	Enum        []string
	Default     string
	Multiline   bool
}

// Input renders as a single-line <input>.
func (p param) Input() bool { return p.Type == "string" || p.Type == "number" || p.Type == "integer" }

func asMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	var m map[string]any
	if b, err := json.Marshal(v); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

// schemaType returns the primary JSON Schema type (handles ["string","null"]).
func schemaType(m map[string]any) string {
	switch t := m["type"].(type) {
	case string:
		return t
	case []any:
		for _, x := range t {
			if s, ok := x.(string); ok && s != "null" {
				return s
			}
		}
	}
	return ""
}

// schemaParams turns an object input schema into form fields. simple reports
// whether every property maps to a plain field (no nested objects/arrays).
func schemaParams(schema any) (params []param, simple bool) {
	m := asMap(schema)
	props := asMap(m["properties"])
	required := map[string]bool{}
	if rs, ok := m["required"].([]any); ok {
		for _, r := range rs {
			if s, ok := r.(string); ok {
				required[s] = true
			}
		}
	}
	simple = true
	for name, raw := range props {
		pm := asMap(raw)
		p := param{Name: name, Required: required[name], Type: schemaType(pm)}
		p.Description, _ = pm["description"].(string)
		if p.Description == "" {
			p.Description, _ = pm["title"].(string)
		}
		if def, ok := pm["default"]; ok && def != nil {
			if s, ok := def.(string); ok {
				p.Default = s
			} else if b, err := json.Marshal(def); err == nil {
				p.Default = string(b)
			}
		}
		if enum, ok := pm["enum"].([]any); ok && len(enum) > 0 {
			allStrings := true
			for _, e := range enum {
				s, ok := e.(string)
				if !ok {
					allStrings = false
					break
				}
				p.Enum = append(p.Enum, s)
			}
			if allStrings {
				p.Type = "enum"
			} else {
				p.Enum = nil
			}
		}
		switch p.Type {
		case "string":
			if mx, ok := pm["maxLength"].(float64); !ok || mx > 200 {
				d := strings.ToLower(p.Description + " " + name)
				p.Multiline = strings.Contains(d, "content") || strings.Contains(d, "body") || strings.Contains(d, "text") || strings.Contains(d, "query") || strings.Contains(d, "prompt")
			}
		case "number", "integer", "boolean", "enum":
		default:
			p.Type = "json"
			simple = false
		}
		params = append(params, p)
	}
	sort.SliceStable(params, func(i, j int) bool {
		if params[i].Required != params[j].Required {
			return params[i].Required
		}
		return params[i].Name < params[j].Name
	})
	return params, simple
}

func defaults(params []param) map[string]string {
	out := map[string]string{}
	for _, p := range params {
		out[p.Name] = p.Default
	}
	return out
}

// exampleArgs builds a JSON skeleton of the arguments for the raw editor.
func exampleArgs(params []param) string {
	m := map[string]any{}
	for _, p := range params {
		if !p.Required && p.Default == "" {
			continue
		}
		switch p.Type {
		case "number", "integer":
			m[p.Name] = 0
		case "boolean":
			m[p.Name] = false
		case "json":
			m[p.Name] = nil
		default:
			m[p.Name] = p.Default
		}
		if p.Default != "" && p.Type != "string" && p.Type != "enum" {
			var v any
			if json.Unmarshal([]byte(p.Default), &v) == nil {
				m[p.Name] = v
			}
		}
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	return string(b)
}

// parseArgs converts submitted form fields ("arg.<name>") into typed arguments.
func parseArgs(r *http.Request, params []param) (map[string]any, error) {
	args := map[string]any{}
	for _, p := range params {
		raw := r.FormValue("arg." + p.Name)
		v := strings.TrimSpace(raw)
		if v == "" {
			if p.Required {
				return nil, fmt.Errorf("%s is required", p.Name)
			}
			continue
		}
		switch p.Type {
		case "integer":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("%s must be an integer", p.Name)
			}
			args[p.Name] = n
		case "number":
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return nil, fmt.Errorf("%s must be a number", p.Name)
			}
			args[p.Name] = f
		case "boolean":
			args[p.Name] = v == "true"
		case "json":
			var x any
			if err := json.Unmarshal([]byte(v), &x); err != nil {
				return nil, fmt.Errorf("%s must be valid JSON", p.Name)
			}
			args[p.Name] = x
		default:
			args[p.Name] = raw
		}
	}
	return args, nil
}

var safeImage = map[string]bool{"image/png": true, "image/jpeg": true, "image/gif": true, "image/webp": true}

// resultParts flattens tool result content for display.
func resultParts(res *mcp.CallToolResult) []resultPart {
	var out []resultPart
	for _, c := range res.Content {
		switch x := c.(type) {
		case *mcp.TextContent:
			out = append(out, resultPart{Kind: "text", Text: x.Text})
		case *mcp.ImageContent:
			if safeImage[x.MIMEType] {
				out = append(out, resultPart{Kind: "image", MIME: x.MIMEType,
					Src: template.URL("data:" + x.MIMEType + ";base64," + base64.StdEncoding.EncodeToString(x.Data))})
				continue
			}
			out = append(out, resultPart{Kind: "json", MIME: x.MIMEType, Text: fmt.Sprintf("<%s image, %d bytes>", x.MIMEType, len(x.Data))})
		default:
			b, _ := json.MarshalIndent(c, "", "  ")
			out = append(out, resultPart{Kind: "json", Text: string(b)})
		}
	}
	return out
}
