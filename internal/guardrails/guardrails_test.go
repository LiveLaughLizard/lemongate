package guardrails

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"lemongate/internal/auth"
	"lemongate/internal/hooks"
	"lemongate/internal/store"
)

func TestLuhn(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"4111111111111111", true},
		{"4111111111111112", false},
		{"5500005555555559", true},
		{"378282246310005", true},
		{"79927398713", true},
		{"79927398710", false},
		{"", false},
		{"12a4", false},
	} {
		if got := Luhn(c.in); got != c.want {
			t.Errorf("Luhn(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestMaskPII(t *testing.T) {
	cases := []struct {
		name, in, want string
		entity         string
	}{
		{"email", "write to jane.doe+x@mail.example.co.uk today", "write to [EMAIL] today", EntityEmail},
		{"card spaced", "card 4111 1111 1111 1111 exp 12/29", "card [CREDIT_CARD] exp 12/29", EntityCreditCard},
		{"card dashed", "4111-1111-1111-1111", "[CREDIT_CARD]", EntityCreditCard},
		{"ssn", "ssn 123-45-6789.", "ssn [SSN].", EntitySSN},
		{"phone us", "call (415) 555-0100 now", "call [PHONE] now", EntityPhone},
		{"phone intl", "call +1 415 555 0100", "call [PHONE]", EntityPhone},
		{"phone e164", "whatsapp +4915112345678", "whatsapp [PHONE]", EntityPhone},
		{"ipv4", "host 10.0.12.254:8080", "host [IP_ADDRESS]:8080", EntityIPv4},
		{"secret key", "use sk-abcdefghijklmnopqrstuvwx please", "use [SECRET] please", EntitySecret},
		{"secret kv", `password: hunter2hunter2`, `password: [SECRET]`, EntitySecret},
		{"jwt", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "Bearer [SECRET]", EntitySecret},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, counts := MaskPII(c.in, nil)
			if got != c.want {
				t.Fatalf("MaskPII(%q) = %q, want %q", c.in, got, c.want)
			}
			if counts[c.entity] == 0 {
				t.Fatalf("expected a %s count, got %v", c.entity, counts)
			}
		})
	}
}

func TestMaskPIINegatives(t *testing.T) {
	for _, in := range []string{
		"order 4111111111111112 is not a card",            // fails Luhn
		"0000 0000 0000 0000",                             // repeated digit
		"ssn 000-12-3456 and 666-12-3456 and 900-12-3456", // invalid SSN ranges
		"version 1.2.3 released",
		"total 1234567890 tokens",
		"999.1.1.1",
		"chatcmpl-1234567890abcdefghijk",
	} {
		if got, counts := MaskPII(in, nil); got != in {
			t.Errorf("MaskPII(%q) = %q (%v), want unchanged", in, got, counts)
		}
	}
}

func TestMaskPIIEntitySubset(t *testing.T) {
	got, counts := MaskPII("mail a@b.io from 10.1.1.1", []string{EntityEmail})
	if got != "mail [EMAIL] from 10.1.1.1" || counts[EntityIPv4] != 0 {
		t.Fatalf("got %q %v", got, counts)
	}
}

func TestRedactKeepsJSONValid(t *testing.T) {
	in := []byte(`{"messages":[{"role":"user","content":"hi\nme@x.com, card 4111111111111111"}],"n":1,"usage":{"prompt_tokens":1234567890}}`)
	out := Redact(in)
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("redacted output is not JSON: %v (%s)", err, out)
	}
	s := string(out)
	if strings.Contains(s, "me@x.com") || strings.Contains(s, "4111111111111111") {
		t.Fatalf("PII left in %s", s)
	}
	if !strings.Contains(s, "1234567890") {
		t.Fatalf("numbers must be preserved: %s", s)
	}
	if out := Redact([]byte("not json a@b.com")); string(out) != `"not json [EMAIL]"` {
		t.Fatalf("non-JSON redact = %s", out)
	}
}

func TestBlocklist(t *testing.T) {
	g := Guardrail{Name: "bl", Kind: KindBlocklist, Mode: ModePre, Action: ActionMask, Enabled: true,
		Config: Config{Words: []string{"secret project", "foo", "c++"}}}
	if err := Validate(&g); err != nil {
		t.Fatal(err)
	}
	r, _ := compile(g)
	segs := []*segment{{text: "The SECRET   Project uses foo, not food; we like C++ too", set: func(string) {}}}
	f := r.check(context.Background(), nil, checkInput{segs: segs, phase: ModePre})
	if !f.hit {
		t.Fatal("expected a hit")
	}
	want := "The [REDACTED] uses [REDACTED], not food; we like [REDACTED] too"
	if f.masked[0] != want {
		t.Fatalf("masked = %q, want %q", f.masked[0], want)
	}
	if f := r.check(context.Background(), nil, checkInput{segs: []*segment{{text: "seafood and foobar"}}, phase: ModePre}); f.hit {
		t.Fatal("word boundaries not honoured")
	}
}

func TestValidate(t *testing.T) {
	bad := []Guardrail{
		{Name: "", Kind: KindPII, Mode: ModePre, Action: ActionBlock, Config: Config{Entities: []string{"email"}}},
		{Name: "x", Kind: "nope", Mode: ModePre, Action: ActionBlock},
		{Name: "x", Kind: KindMaxLength, Mode: ModePre, Action: ActionMask, Config: Config{MaxChars: 10}},
		{Name: "x", Kind: KindRegex, Mode: ModePre, Action: ActionBlock, Config: Config{Patterns: []Pattern{{Pattern: "("}}}},
		{Name: "x", Kind: KindPII, Mode: ModePre, Action: ActionBlock, Config: Config{Entities: []string{"dna"}}},
		{Name: "x", Kind: KindLLMJudge, Mode: ModePre, Action: ActionBlock, Config: Config{Model: "m"}},
	}
	for i, g := range bad {
		if err := Validate(&g); err == nil {
			t.Errorf("case %d: expected validation error", i)
		}
	}
}

func newEngine(t *testing.T, gs ...Guardrail) *Engine {
	t.Helper()
	e := New(nil, nil, nil, nil)
	for i := range gs {
		if err := Validate(&gs[i]); err != nil {
			t.Fatalf("%s: %v", gs[i].Name, err)
		}
	}
	e.load(gs)
	return e
}

func TestApplicability(t *testing.T) {
	e := newEngine(t,
		Guardrail{Name: "global", Kind: KindMaxLength, Mode: ModePre, Action: ActionBlock, DefaultOn: true, Enabled: true, Config: Config{MaxChars: 100}},
		Guardrail{Name: "global-off", Kind: KindMaxLength, Mode: ModePre, Action: ActionBlock, DefaultOn: true, Enabled: false, Config: Config{MaxChars: 100}},
		Guardrail{Name: "keyg", Kind: KindPII, Mode: ModeBoth, Action: ActionMask, Enabled: true, Config: Config{Entities: []string{"email"}}},
		Guardrail{Name: "teamg", Kind: KindBlocklist, Mode: ModePost, Action: ActionBlock, Enabled: true, Config: Config{Words: []string{"x"}}},
		Guardrail{Name: "asked", Kind: KindRegex, Mode: ModePre, Action: ActionLog, Enabled: true, Config: Config{Patterns: []Pattern{{Pattern: "a+"}}}},
	)
	names := func(rs []*rule) string {
		var s []string
		for _, r := range rs {
			s = append(s, r.g.Name)
		}
		return strings.Join(s, ",")
	}
	if got := names(e.applicable(hooks.CallInfo{}, ModePre)); got != "global" {
		t.Fatalf("anonymous pre = %q", got)
	}
	p := &auth.Principal{Key: &store.Key{ID: "k", Guardrails: []string{"keyg", "missing"}}, Team: &store.Team{Guardrails: []string{"teamg"}}}
	info := hooks.CallInfo{Principal: p, RequestedGuardrails: []string{"asked", "keyg"}}
	// Ordered by kind: max_length, blocklist, regex, pii, llm_judge.
	if got := names(e.applicable(info, ModePre)); got != "global,asked,keyg" {
		t.Fatalf("pre = %q", got)
	}
	if got := names(e.applicable(info, ModePost)); got != "teamg,keyg" {
		t.Fatalf("post = %q", got)
	}
}

func TestPreCallMaskAndBlock(t *testing.T) {
	e := newEngine(t,
		Guardrail{Name: "pii", Kind: KindPII, Mode: ModeBoth, Action: ActionMask, DefaultOn: true, Enabled: true, Config: Config{Entities: AllEntityIDs()}},
		Guardrail{Name: "nope", Kind: KindBlocklist, Mode: ModePre, Action: ActionBlock, Enabled: true, Config: Config{Words: []string{"forbidden"}}},
	)
	body := map[string]any{"messages": []any{
		map[string]any{"role": "system", "content": "be nice"},
		map[string]any{"role": "user", "content": []any{
			map[string]any{"type": "text", "text": "my email is a@b.com"},
			map[string]any{"type": "image_url", "image_url": map[string]any{"url": "data:..."}},
		}},
	}}
	if err := e.PreCall(context.Background(), hooks.CallInfo{}, body); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(body)
	if !strings.Contains(string(b), "my email is [EMAIL]") {
		t.Fatalf("not masked: %s", b)
	}

	comp := map[string]any{"prompt": []any{"ok", "this is forbidden"}}
	err := e.PreCall(context.Background(), hooks.CallInfo{RequestedGuardrails: []string{"nope"}}, comp)
	var gb *hooks.GuardrailBlock
	if !errors.As(err, &gb) || gb.Guardrail != "nope" {
		t.Fatalf("expected block, got %v", err)
	}

	resp := map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": "reach me at 10.0.0.1 or x@y.org"}}}}
	if err := e.PostCall(context.Background(), hooks.CallInfo{}, resp); err != nil {
		t.Fatal(err)
	}
	got := resp["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)["content"]
	if got != "reach me at [IP_ADDRESS] or [EMAIL]" {
		t.Fatalf("response not masked: %v", got)
	}
}

func TestInputSegments(t *testing.T) {
	body := map[string]any{
		"input": []any{
			"plain a@b.com",
			map[string]any{"role": "user", "content": []any{map[string]any{"type": "input_text", "text": "c@d.com"}}},
		},
	}
	segs := requestSegments(body)
	if len(segs) != 2 {
		t.Fatalf("segments = %d", len(segs))
	}
	for _, s := range segs {
		m, _ := MaskPII(s.text, nil)
		s.set(m)
	}
	b, _ := json.Marshal(body)
	if strings.Contains(string(b), "@") {
		t.Fatalf("not rewritten: %s", b)
	}
}

func TestMaxLengthAndTestBench(t *testing.T) {
	e := newEngine(t,
		Guardrail{Name: "short", Kind: KindMaxLength, Mode: ModePre, Action: ActionBlock, Enabled: false, Config: Config{MaxChars: 5}},
		Guardrail{Name: "re", Kind: KindRegex, Mode: ModePre, Action: ActionMask, Enabled: true,
			Config: Config{Patterns: []Pattern{{Pattern: `(?i)order-\d+`, Replacement: "[ORDER]"}}}},
	)
	res, err := e.Test(context.Background(), []string{"re"}, "see ORDER-123", ModePre)
	if err != nil || res.Output != "see [ORDER]" || res.Blocked {
		t.Fatalf("bench = %+v, %v", res, err)
	}
	res, _ = e.Test(context.Background(), []string{"re", "short"}, "see ORDER-123", ModePre)
	if !res.Blocked || res.By != "short" {
		t.Fatalf("expected max_length block, got %+v", res)
	}
	if _, err := e.Test(context.Background(), []string{"ghost"}, "x", ModePre); err == nil {
		t.Fatal("expected unknown guardrail error")
	}
}

func TestParseVerdict(t *testing.T) {
	ok, why, err := parseVerdict("<think>hmm</think>\n```json\n{\"allowed\": false, \"reason\": \"medical advice\"}\n```")
	if err != nil || ok || why != "medical advice" {
		t.Fatalf("got %v %q %v", ok, why, err)
	}
	if _, _, err := parseVerdict("sure, looks fine"); err == nil {
		t.Fatal("expected error for prose")
	}
	if _, _, err := parseVerdict(`{"reason":"x"}`); err == nil {
		t.Fatal("expected error when allowed is missing")
	}
}

func TestJudgeFailOpenClosed(t *testing.T) {
	// No registry: the judge cannot run, which exercises the failure policy.
	open := Guardrail{Name: "j-open", Kind: KindLLMJudge, Mode: ModePre, Action: ActionBlock, Enabled: true,
		Config: Config{Model: "m", Policy: "no spam", FailOpen: true}}
	closed := Guardrail{Name: "j-closed", Kind: KindLLMJudge, Mode: ModePre, Action: ActionBlock, Enabled: true,
		Config: Config{Model: "m", Policy: "no spam"}}
	e := newEngine(t, open, closed)
	body := func() map[string]any { return map[string]any{"prompt": "hello"} }
	if err := e.PreCall(context.Background(), hooks.CallInfo{RequestedGuardrails: []string{"j-open"}}, body()); err != nil {
		t.Fatalf("fail-open should allow: %v", err)
	}
	if err := e.PreCall(context.Background(), hooks.CallInfo{RequestedGuardrails: []string{"j-closed"}}, body()); err == nil {
		t.Fatal("fail-closed should block")
	}
}
