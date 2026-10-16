// Package guardrails inspects requests and responses flowing through the gateway.
//
// A guardrail is a named, persisted rule (table `guardrails`) of one kind:
//
//	pii               detect and mask personal data and secrets (regional entity library)
//	blocklist         keywords / phrases and built-in content categories, on word boundaries
//	regex             custom patterns, each with an optional replacement
//	max_length        maximum characters of request text
//	prompt_injection  heuristic detection of injection and jailbreak techniques
//	code_execution    executable or destructive code (shell, SQL, Python, ...)
//	tool_policy       allow/deny lists for tool definitions and tool calls
//	semantic          embedding similarity to known attack examples (vLLM embedding model)
//	guard_model       purpose-built safety models served by vLLM (Llama Guard, Granite
//	                  Guardian, Qwen3Guard, ShieldGemma, Prompt Guard classifier)
//	llm_judge         ask any chat model whether the text satisfies a written policy
//
// Each guardrail runs before the upstream call ("pre"), on the response ("post")
// or both, and either blocks, masks (rewrites the body in place) or only logs.
// Guardrails can be grouped into policies (table `guardrail_policies`). A call is
// checked by every enabled default-on guardrail and policy, plus those attached to
// its key or team, or named in the body's "guardrails" field.
package guardrails

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
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgxpool"

	"lemongate/internal/hooks"
	"lemongate/internal/metrics"
	"lemongate/internal/routing"
	"lemongate/internal/settings"
)

// Kinds, modes and actions.
const (
	KindPII       = "pii"
	KindBlocklist = "blocklist"
	KindRegex     = "regex"
	KindMaxLength = "max_length"
	KindLLMJudge  = "llm_judge"

	KindPromptInjection = "prompt_injection"
	KindCodeExecution   = "code_execution"
	KindToolPolicy      = "tool_policy"
	KindSemantic        = "semantic"
	KindGuardModel      = "guard_model"

	// Guard model families (Config.Family).
	FamilyLlamaGuard      = "llama_guard"
	FamilyGraniteGuardian = "granite_guardian"
	FamilyQwen3Guard      = "qwen3_guard"
	FamilyShieldGemma     = "shieldgemma"
	FamilyPromptGuard     = "prompt_guard"

	ModePre  = "pre"
	ModePost = "post"
	ModeBoth = "both"

	ActionBlock = "block"
	ActionMask  = "mask"
	ActionLog   = "log"
)

var (
	Kinds = []string{KindPII, KindBlocklist, KindRegex, KindMaxLength, KindPromptInjection, KindCodeExecution,
		KindToolPolicy, KindSemantic, KindGuardModel, KindLLMJudge}
	Families = []string{FamilyLlamaGuard, FamilyGraniteGuardian, FamilyQwen3Guard, FamilyShieldGemma, FamilyPromptGuard}
	Modes    = []string{ModePre, ModePost, ModeBoth}
	Actions  = []string{ActionBlock, ActionMask, ActionLog}
)

// kindOrder runs cheap checks first and the LLM judge last, so a block by a
// local rule avoids a model call and the judge sees already-masked text.
var kindOrder = map[string]int{KindMaxLength: 0, KindToolPolicy: 1, KindBlocklist: 2, KindRegex: 3, KindCodeExecution: 4,
	KindPII: 5, KindPromptInjection: 6, KindSemantic: 7, KindGuardModel: 8, KindLLMJudge: 9}

// Pattern is one custom regex with an optional replacement used when masking.
type Pattern struct {
	Pattern     string `json:"pattern"`
	Replacement string `json:"replacement,omitempty"`
}

// Config holds the kind-specific settings of a guardrail (stored as jsonb).
type Config struct {
	Entities    []string  `json:"entities,omitempty"`    // pii: entity ids (see Entities)
	Words       []string  `json:"words,omitempty"`       // blocklist: custom terms
	Categories  []string  `json:"categories,omitempty"`  // blocklist: built-in content categories
	Patterns    []Pattern `json:"patterns,omitempty"`    // regex
	Replacement string    `json:"replacement,omitempty"` // blocklist / regex default mask
	MaxChars    int       `json:"max_chars,omitempty"`   // max_length

	// Model is a gateway model name: llm_judge, guard_model (chat/completion or classify
	// model) and semantic (embedding model).
	Model  string `json:"model,omitempty"`
	Policy string `json:"policy,omitempty"` // llm_judge: written policy; shieldgemma: custom principle

	// guard_model
	Family  string   `json:"family,omitempty"`  // one of Families
	Hazards []string `json:"hazards,omitempty"` // enabled hazard / risk ids for the family; empty = family defaults
	// StrictControversial treats Qwen3Guard's "Controversial" verdict as unsafe.
	StrictControversial bool `json:"strict_controversial,omitempty"`

	// Threshold is a 0–1 score above which content is flagged: prompt_injection
	// (sensitivity), semantic (cosine similarity), shieldgemma / prompt_guard (probability).
	Threshold float64 `json:"threshold,omitempty"`

	Languages  []string `json:"languages,omitempty"`   // code_execution: languages to detect (empty = all)
	AllowTools []string `json:"allow_tools,omitempty"` // tool_policy: glob patterns; empty = allow all not denied
	DenyTools  []string `json:"deny_tools,omitempty"`  // tool_policy: glob patterns
	Examples   []string `json:"examples,omitempty"`    // semantic: known-bad example texts

	FailOpen       bool `json:"fail_open,omitempty"`       // model-backed kinds: allow when the model is unavailable
	TimeoutSeconds int  `json:"timeout_seconds,omitempty"` // model-backed kinds
}

// Guardrail is a persisted guardrail definition.
type Guardrail struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Kind        string    `json:"kind"`
	Mode        string    `json:"mode"`
	Action      string    `json:"action"`
	Config      Config    `json:"config"`
	DefaultOn   bool      `json:"default_on"`
	Enabled     bool      `json:"enabled"`
	Description string    `json:"description"`
	Preset      string    `json:"preset"` // id of the preset that created it, if any
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// AppliesTo reports whether the guardrail runs in the given phase ("pre"/"post").
func (g Guardrail) AppliesTo(phase string) bool { return g.Mode == ModeBoth || g.Mode == phase }

// CanMask reports whether the kind supports the mask action.
func CanMask(kind string) bool {
	if impl, ok := kindImpls[kind]; ok {
		return impl.canMask
	}
	return kind == KindPII || kind == KindBlocklist || kind == KindRegex
}

// Engine implements hooks.Guardrails.
type Engine struct {
	pool     *pgxpool.Pool
	settings *settings.Store
	client   *http.Client
	registry *routing.Registry

	state  atomic.Pointer[state]
	events chan Event
}

type state struct {
	byName   map[string]*rule
	defaults []string            // guardrails applied to every call (default-on guardrails and policies)
	policies map[string][]string // enabled policy name -> guardrail names
	errs     map[string]string
}

func New(pool *pgxpool.Pool, st *settings.Store, client *http.Client, reg *routing.Registry) *Engine {
	if client == nil {
		client = http.DefaultClient
	}
	e := &Engine{pool: pool, settings: st, client: client, registry: reg, events: make(chan Event, 2048)}
	e.state.Store(&state{byName: map[string]*rule{}, policies: map[string][]string{}, errs: map[string]string{}})
	if pool != nil {
		go e.writeEvents()
		go e.refreshLoop()
	}
	return e
}

// RefreshInterval is how often definitions are re-read so edits made through
// another replica take effect without a restart.
var RefreshInterval = 30 * time.Second

func (e *Engine) refreshLoop() {
	t := time.NewTicker(RefreshInterval)
	defer t.Stop()
	for range t.C {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := e.Reload(ctx); err != nil {
			slog.Debug("guardrails refresh", "err", err)
		}
		cancel()
	}
}

// Reload re-reads every guardrail from the database. Call it after edits.
func (e *Engine) Reload(ctx context.Context) error {
	list, err := e.List(ctx)
	if err != nil {
		return err
	}
	pols, err := e.ListPolicies(ctx)
	if err != nil {
		return err
	}
	e.load(list, pols...)
	return nil
}

// load compiles definitions into the active rule set.
func (e *Engine) load(list []Guardrail, policies ...Policy) {
	st := &state{byName: map[string]*rule{}, policies: map[string][]string{}, errs: map[string]string{}}
	for _, g := range list {
		r, err := compile(g)
		if err != nil {
			slog.Warn("guardrail disabled: invalid config", "guardrail", g.Name, "err", err)
			st.errs[g.Name] = err.Error()
			continue
		}
		st.byName[g.Name] = r
		if g.Enabled && g.DefaultOn {
			st.defaults = append(st.defaults, g.Name)
		}
	}
	for _, p := range policies {
		if !p.Enabled {
			continue
		}
		st.policies[p.Name] = p.Guardrails
		if p.DefaultOn {
			st.defaults = append(st.defaults, p.Guardrails...)
		}
	}
	e.state.Store(st)
}

// CompileError returns why a stored guardrail could not be loaded ("" if fine).
func (e *Engine) CompileError(name string) string { return e.state.Load().errs[name] }

// Names returns the names of all loaded guardrails.
func (e *Engine) Names() []string {
	st := e.state.Load()
	out := make([]string, 0, len(st.byName))
	for n := range st.byName {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// applicable returns the enabled rules that apply to a call in a phase, in execution order.
func (e *Engine) applicable(info hooks.CallInfo, phase string) []*rule {
	st := e.state.Load()
	if len(st.byName) == 0 {
		return nil
	}
	names := append([]string{}, st.defaults...)
	if p := info.Principal; p != nil {
		if p.Key != nil {
			names = append(names, p.Key.Guardrails...)
			names = append(names, st.expandPolicies(p.Key.Policies)...)
		}
		if p.Team != nil {
			names = append(names, p.Team.Guardrails...)
			names = append(names, st.expandPolicies(p.Team.Policies)...)
		}
	}
	// Names requested in the body may refer to guardrails or policies.
	for _, n := range info.RequestedGuardrails {
		names = append(names, n)
		names = append(names, st.expandPolicies([]string{n})...)
	}
	seen := map[string]bool{}
	var out []*rule
	for _, n := range names {
		n = strings.TrimSpace(n)
		if seen[n] {
			continue
		}
		seen[n] = true
		r := st.byName[n]
		if r == nil || !r.g.Enabled || !r.g.AppliesTo(phase) {
			continue
		}
		out = append(out, r)
	}
	sortRules(out)
	return out
}

func (st *state) expandPolicies(names []string) []string {
	var out []string
	for _, n := range names {
		out = append(out, st.policies[strings.TrimSpace(n)]...)
	}
	return out
}

func sortRules(rs []*rule) {
	slices.SortStableFunc(rs, func(a, b *rule) int {
		if d := kindOrder[a.g.Kind] - kindOrder[b.g.Kind]; d != 0 {
			return d
		}
		return strings.Compare(a.g.Name, b.g.Name)
	})
}

// --- hooks.Guardrails ---

func (e *Engine) PreCall(ctx context.Context, info hooks.CallInfo, body map[string]any) error {
	rules := e.applicable(info, ModePre)
	if len(rules) == 0 {
		return nil
	}
	res := e.run(ctx, rules, checkInput{segs: requestSegments(body), phase: ModePre, info: &info, body: body}, false)
	if res.Block != nil {
		return res.Block
	}
	return nil
}

func (e *Engine) PostCall(ctx context.Context, info hooks.CallInfo, body map[string]any) error {
	rules := e.applicable(info, ModePost)
	if len(rules) == 0 {
		return nil
	}
	res := e.run(ctx, rules, checkInput{segs: responseSegments(body), phase: ModePost, info: &info, body: body}, false)
	if res.Block != nil {
		return res.Block
	}
	return nil
}

// PostStream checks the assembled text of a streamed response. The response has
// already been delivered, so every intervention is only logged.
func (e *Engine) PostStream(ctx context.Context, info hooks.CallInfo, text string) {
	rules := e.applicable(info, ModePost)
	if len(rules) == 0 || text == "" {
		return
	}
	seg := &segment{text: text, set: func(string) {}}
	e.run(ctx, rules, checkInput{segs: []*segment{seg}, phase: ModePost, info: &info}, true)
}

// Redact masks PII in stored log payloads using every built-in detector,
// independently of the configured guardrails. Input and output are JSON.
func (e *Engine) Redact(b []byte) []byte { return Redact(b) }

// Redact masks PII inside every string value of a JSON document.
func Redact(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	var v any
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		// Not JSON: mask as plain text, then re-encode as a JSON string so the
		// output stays valid for jsonb columns.
		s, _ := MaskPII(string(b), nil)
		out, _ := json.Marshal(s)
		return out
	}
	out, err := json.Marshal(redactValue(v))
	if err != nil {
		return b
	}
	return out
}

// --- execution ---

// Step is the outcome of one guardrail on one piece of text.
type Step struct {
	Guardrail string `json:"guardrail"`
	Kind      string `json:"kind"`
	Action    string `json:"action"`
	// Outcome: passed | masked | blocked | logged | error
	Outcome string `json:"outcome"`
	Detail  string `json:"detail"`
}

// Result is the combined outcome of running a set of guardrails.
type Result struct {
	Block *hooks.GuardrailBlock
	Steps []Step
}

func (e *Engine) run(ctx context.Context, rules []*rule, in checkInput, logOnly bool) Result {
	var res Result
	segs, phase, info := in.segs, in.phase, in.info
	for _, r := range rules {
		f := r.check(ctx, e, in)
		step := Step{Guardrail: r.g.Name, Kind: r.g.Kind, Action: r.g.Action, Outcome: "passed", Detail: f.detail}
		if f.err != nil {
			step.Outcome, step.Detail = "error", f.err.Error()
			if r.g.Config.FailOpen {
				e.record(info, r.g.Name, phase, "error", "model check unavailable, allowed (fail-open): "+f.err.Error())
				res.Steps = append(res.Steps, step)
				continue
			}
			// Fail-closed: treat the unavailable verdict as a violation.
			f = finding{hit: true, reason: "policy check unavailable", detail: "model check unavailable (fail-closed): " + f.err.Error()}
			step.Detail = f.detail
		}
		if !f.hit {
			res.Steps = append(res.Steps, step)
			continue
		}
		action := r.g.Action
		if action == ActionMask && (!CanMask(r.g.Kind) || f.masked == nil) {
			action = ActionBlock
		}
		if logOnly {
			e.record(info, r.g.Name, phase, ActionLog, fmt.Sprintf("%s (would %s; streamed)", f.detail, action))
			step.Outcome, step.Detail = "logged", f.detail
			res.Steps = append(res.Steps, step)
			continue
		}
		switch action {
		case ActionMask:
			for i, s := range segs {
				if m := f.masked[i]; m != s.text {
					s.text = m
					s.set(m)
				}
			}
			e.record(info, r.g.Name, phase, "mask", f.detail)
			step.Outcome = "masked"
		case ActionLog:
			e.record(info, r.g.Name, phase, ActionLog, f.detail)
			step.Outcome = "logged"
		default:
			e.record(info, r.g.Name, phase, ActionBlock, f.detail)
			step.Outcome = "blocked"
			reason := f.reason
			if phase == ModePost {
				reason = "response " + reason
			}
			res.Block = &hooks.GuardrailBlock{Guardrail: r.g.Name, Reason: reason}
			res.Steps = append(res.Steps, step)
			return res
		}
		res.Steps = append(res.Steps, step)
	}
	return res
}

// TestResult is returned by the console test bench.
type TestResult struct {
	Input   string
	Output  string
	Blocked bool
	By      string
	Reason  string
	Steps   []Step
}

// Test runs the named guardrails (enabled or not, ignoring mode) against text
// without recording events. phase selects the judge's framing ("pre" or "post").
func (e *Engine) Test(ctx context.Context, names []string, text, phase string) (TestResult, error) {
	st := e.state.Load()
	var rules []*rule
	for _, n := range names {
		r := st.byName[n]
		if r == nil {
			if msg := st.errs[n]; msg != "" {
				return TestResult{}, fmt.Errorf("guardrail %q has an invalid config: %s", n, msg)
			}
			return TestResult{}, fmt.Errorf("unknown guardrail %q", n)
		}
		rules = append(rules, r)
	}
	sortRules(rules)
	if phase != ModePost {
		phase = ModePre
	}
	out := text
	seg := &segment{text: text, set: func(v string) { out = v }}
	// A synthetic body gives conversation-aware kinds (guard models) the same shape as live traffic.
	body := map[string]any{"messages": []any{map[string]any{"role": "user", "content": text}}}
	if phase == ModePost {
		body = map[string]any{"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": text}}}}
	}
	res := e.run(ctx, rules, checkInput{segs: []*segment{seg}, phase: phase, body: body}, false)
	tr := TestResult{Input: text, Output: out, Steps: res.Steps}
	if res.Block != nil {
		tr.Blocked, tr.By, tr.Reason = true, res.Block.Guardrail, res.Block.Reason
	}
	return tr, nil
}

// --- events ---

// Event is one guardrail intervention.
type Event struct {
	ID        int64     `json:"id"`
	At        time.Time `json:"at"`
	Guardrail string    `json:"guardrail"`
	RequestID string    `json:"request_id"`
	KeyID     string    `json:"key_id"`
	KeyAlias  string    `json:"key_alias"`
	Phase     string    `json:"phase"`
	Action    string    `json:"action"`
	Detail    string    `json:"detail"`
}

func (e *Engine) record(info *hooks.CallInfo, name, phase, action, detail string) {
	if info == nil { // test bench
		return
	}
	metrics.GuardrailActions.WithLabelValues(name, action).Inc()
	ev := Event{At: time.Now(), Guardrail: name, RequestID: info.RequestID, KeyID: info.Principal.KeyID(), Phase: phase, Action: action, Detail: detail}
	select {
	case e.events <- ev:
	default:
		slog.Warn("guardrail event queue full; dropping event", "guardrail", name)
	}
}

func (e *Engine) writeEvents() {
	for ev := range e.events {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		var keyID any
		if ev.KeyID != "" {
			keyID = ev.KeyID
		}
		if _, err := e.pool.Exec(ctx, `INSERT INTO guardrail_events (at, guardrail, request_id, key_id, phase, action, detail)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`, ev.At, ev.Guardrail, ev.RequestID, keyID, ev.Phase, ev.Action, truncate(ev.Detail, 1000)); err != nil {
			slog.Warn("write guardrail event", "err", err)
		}
		cancel()
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

// ErrNotFound is returned by Get for an unknown id.
var ErrNotFound = errors.New("guardrail not found")
