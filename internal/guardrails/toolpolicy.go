package guardrails

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
)

func init() {
	registerKind(KindToolPolicy, kindImpl{validate: validateToolPolicy, compile: compileToolPolicy, check: checkToolPolicy})
}

type toolPolicy struct {
	allow, deny []string // lower-cased glob patterns
}

func normalizeGlobs(xs []string) ([]string, error) {
	xs = cleanList(xs)
	for i, p := range xs {
		p = strings.ToLower(p)
		if _, err := path.Match(p, ""); err != nil {
			return nil, fmt.Errorf("invalid tool pattern %q: %v", xs[i], err)
		}
		xs[i] = p
	}
	return cleanList(xs), nil
}

func validateToolPolicy(c *Config) error {
	var err error
	if c.AllowTools, err = normalizeGlobs(c.AllowTools); err != nil {
		return err
	}
	if c.DenyTools, err = normalizeGlobs(c.DenyTools); err != nil {
		return err
	}
	if len(c.AllowTools) == 0 && len(c.DenyTools) == 0 {
		return errors.New("add at least one allowed or denied tool pattern")
	}
	return nil
}

func compileToolPolicy(r *rule) error {
	allow, err := normalizeGlobs(r.g.Config.AllowTools)
	if err != nil {
		return err
	}
	deny, err := normalizeGlobs(r.g.Config.DenyTools)
	if err != nil {
		return err
	}
	r.ext = &toolPolicy{allow: allow, deny: deny}
	return nil
}

func matchAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if ok, _ := path.Match(p, name); ok {
			return true
		}
	}
	return false
}

// allowed reports whether a tool name passes the policy.
func (tp *toolPolicy) allowed(name string) bool {
	n := strings.ToLower(name)
	if matchAny(tp.deny, n) {
		return false
	}
	return len(tp.allow) == 0 || matchAny(tp.allow, n)
}

func checkToolPolicy(_ context.Context, _ *Engine, r *rule, in checkInput) finding {
	tp, _ := r.ext.(*toolPolicy)
	if tp == nil || in.body == nil {
		return finding{}
	}
	var names []string
	if in.phase == ModePost {
		names = responseToolNames(in.body)
	} else {
		names = requestToolNames(in.body)
	}
	var bad []string
	seen := map[string]bool{}
	for _, n := range names {
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		if !tp.allowed(n) {
			bad = append(bad, n)
		}
	}
	if len(bad) == 0 {
		return finding{}
	}
	what := "tool definitions"
	if in.phase == ModePost {
		what = "tool calls"
	}
	return finding{hit: true, detail: "disallowed " + what + ": " + strings.Join(bad, ", "),
		reason: "uses a tool that is not allowed (" + strings.Join(bad, ", ") + ")"}
}

// toolName reads a name from {"function":{"name":…}} or {"name":…}.
func toolName(v any) string {
	m, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	if f, ok := m["function"].(map[string]any); ok {
		if n, ok := f["name"].(string); ok {
			return n
		}
	}
	if n, ok := m["name"].(string); ok {
		return n
	}
	return ""
}

func toolCallNames(out []string, msg map[string]any) []string {
	if calls, ok := msg["tool_calls"].([]any); ok {
		for _, c := range calls {
			out = append(out, toolName(c))
		}
	}
	if fc, ok := msg["function_call"].(map[string]any); ok { // legacy functions API
		if n, ok := fc["name"].(string); ok {
			out = append(out, n)
		}
	}
	return out
}

// requestToolNames returns the tools offered in a request (tools[], legacy
// functions[]) and the tools the assistant already called in its history.
func requestToolNames(body map[string]any) []string {
	var out []string
	for _, k := range []string{"tools", "functions"} {
		if arr, ok := body[k].([]any); ok {
			for _, t := range arr {
				out = append(out, toolName(t))
			}
		}
	}
	if msgs, ok := body["messages"].([]any); ok {
		for _, m := range msgs {
			if mm, ok := m.(map[string]any); ok && mm["role"] == "assistant" {
				out = toolCallNames(out, mm)
			}
		}
	}
	// Responses API: input items of type function_call.
	if items, ok := body["input"].([]any); ok {
		for _, it := range items {
			if im, ok := it.(map[string]any); ok && im["type"] == "function_call" {
				out = append(out, toolName(im))
			}
		}
	}
	return out
}

// responseToolNames returns the tools a response calls.
func responseToolNames(body map[string]any) []string {
	var out []string
	if choices, ok := body["choices"].([]any); ok {
		for _, c := range choices {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			if msg, ok := cm["message"].(map[string]any); ok {
				out = toolCallNames(out, msg)
			}
		}
	}
	if items, ok := body["output"].([]any); ok {
		for _, it := range items {
			if im, ok := it.(map[string]any); ok && im["type"] == "function_call" {
				out = append(out, toolName(im))
			}
		}
	}
	return out
}
