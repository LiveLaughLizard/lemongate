package guardrails

import (
	"context"
	"strings"
	"testing"
)

func toolRule(t *testing.T, allow, deny []string) *rule {
	t.Helper()
	g := Guardrail{Name: "tools", Kind: KindToolPolicy, Mode: ModeBoth, Action: ActionBlock, Enabled: true,
		Config: Config{AllowTools: allow, DenyTools: deny}}
	if err := Validate(&g); err != nil {
		t.Fatal(err)
	}
	r, err := compile(g)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func fn(name string) map[string]any {
	return map[string]any{"type": "function", "function": map[string]any{"name": name}}
}

func TestToolPolicyPre(t *testing.T) {
	body := map[string]any{
		"tools": []any{fn("get_weather"), fn("Shell_Exec")},
		"messages": []any{
			map[string]any{"role": "user", "content": "hi"},
			map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{"id": "1", "type": "function", "function": map[string]any{"name": "db.drop_all", "arguments": "{}"}}}},
		},
	}
	r := toolRule(t, nil, []string{"shell_*"})
	f := r.check(context.Background(), nil, checkInput{phase: ModePre, body: body})
	if !f.hit || !strings.Contains(f.detail, "Shell_Exec") || strings.Contains(f.detail, "get_weather") {
		t.Fatalf("deny finding = %+v", f)
	}

	r = toolRule(t, []string{"get_*", "search"}, nil)
	f = r.check(context.Background(), nil, checkInput{phase: ModePre, body: body})
	if !f.hit || !strings.Contains(f.detail, "Shell_Exec") || !strings.Contains(f.detail, "db.drop_all") {
		t.Fatalf("allow finding = %+v", f)
	}

	// Deny wins over allow.
	r = toolRule(t, []string{"*"}, []string{"db.*"})
	f = r.check(context.Background(), nil, checkInput{phase: ModePre, body: body})
	if !f.hit || f.detail != "disallowed tool definitions: db.drop_all" {
		t.Fatalf("deny-over-allow finding = %+v", f)
	}

	// Everything allowed.
	r = toolRule(t, []string{"*"}, []string{"rm_*"})
	if f := r.check(context.Background(), nil, checkInput{phase: ModePre, body: body}); f.hit {
		t.Fatalf("unexpected hit %+v", f)
	}
	// No body (stream / test bench): nothing to check.
	if f := r.check(context.Background(), nil, checkInput{phase: ModePre}); f.hit {
		t.Fatal("hit without body")
	}
}

func TestToolPolicyPost(t *testing.T) {
	body := map[string]any{"choices": []any{map[string]any{"index": 0, "message": map[string]any{
		"role": "assistant", "content": nil,
		"tool_calls": []any{map[string]any{"id": "c1", "type": "function", "function": map[string]any{"name": "send_email", "arguments": "{}"}}},
	}}}}
	r := toolRule(t, nil, []string{"SEND_*"})
	f := r.check(context.Background(), nil, checkInput{phase: ModePost, body: body})
	if !f.hit || f.detail != "disallowed tool calls: send_email" || !strings.Contains(f.reason, "send_email") {
		t.Fatalf("post finding = %+v", f)
	}
	// Tool definitions in a request body are not looked at post-call.
	r = toolRule(t, nil, []string{"get_weather"})
	if f := r.check(context.Background(), nil, checkInput{phase: ModePost, body: map[string]any{"tools": []any{fn("get_weather")}}}); f.hit {
		t.Fatalf("post looked at tools: %+v", f)
	}
}

func TestToolPolicyValidate(t *testing.T) {
	g := Guardrail{Name: "t", Kind: KindToolPolicy, Mode: ModePre, Action: ActionBlock}
	if err := Validate(&g); err == nil {
		t.Fatal("empty lists accepted")
	}
	g.Config.DenyTools = []string{"[bad"}
	if err := Validate(&g); err == nil {
		t.Fatal("bad glob accepted")
	}
	g.Config.DenyTools = []string{" Exec_* ", "exec_*"}
	if err := Validate(&g); err != nil {
		t.Fatal(err)
	}
	if len(g.Config.DenyTools) != 1 || g.Config.DenyTools[0] != "exec_*" {
		t.Fatalf("not normalized: %v", g.Config.DenyTools)
	}
	g.Action = ActionMask
	if err := Validate(&g); err == nil {
		t.Fatal("mask accepted for tool_policy")
	}
}
