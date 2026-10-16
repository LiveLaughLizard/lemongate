package guardrails

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

// guard_model: purpose-built safety classifiers served by vLLM. Each family has its
// own request format and verdict parser (guardmodel_<family>.go); this file holds
// the catalog, validation and the conversation builder they share.

// Hazard is one category / risk a guard model family can detect.
type Hazard struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// FamilyMeta describes a guard model family for the console and presets.
type FamilyMeta struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
	// Endpoint is the vLLM API the family uses: chat | completions | classify.
	Endpoint         string   `json:"endpoint"`
	Hazards          []Hazard `json:"hazards"`
	DefaultHazards   []string `json:"default_hazards"`
	UsesThreshold    bool     `json:"uses_threshold"`
	DefaultThreshold float64  `json:"default_threshold"`
	Phases           []string `json:"phases"` // which of pre/post the family supports
}

var familyCatalog = []FamilyMeta{
	{
		ID: FamilyLlamaGuard, Label: "Llama Guard",
		Description: "Llama Guard 3 / 4 content-safety classifier (MLCommons hazard taxonomy S1–S14). Checks user prompts and assistant responses in conversation context.",
		Endpoint:    "chat",
		Hazards: []Hazard{
			{"S1", "Violent Crimes"}, {"S2", "Non-Violent Crimes"}, {"S3", "Sex-Related Crimes"},
			{"S4", "Child Sexual Exploitation"}, {"S5", "Defamation"}, {"S6", "Specialized Advice"},
			{"S7", "Privacy"}, {"S8", "Intellectual Property"}, {"S9", "Indiscriminate Weapons"},
			{"S10", "Hate"}, {"S11", "Suicide & Self-Harm"}, {"S12", "Sexual Content"},
			{"S13", "Elections"}, {"S14", "Code Interpreter Abuse"},
		},
		DefaultHazards: []string{"S1", "S2", "S3", "S4", "S5", "S7", "S8", "S9", "S10", "S11", "S12", "S13", "S14"},
		Phases:         []string{ModePre, ModePost},
	},
	{
		ID: FamilyGraniteGuardian, Label: "Granite Guardian",
		Description: "Granite Guardian risk detector. Runs one yes/no check per enabled risk, in parallel; jailbreak applies to prompts only.",
		Endpoint:    "chat",
		Hazards: []Hazard{
			{"harm", "General harm"}, {"social_bias", "Social bias"}, {"jailbreak", "Jailbreak"},
			{"violence", "Violence"}, {"profanity", "Profanity"}, {"sexual_content", "Sexual content"},
			{"unethical_behavior", "Unethical behavior"},
		},
		DefaultHazards: []string{"harm", "jailbreak"},
		Phases:         []string{ModePre, ModePost},
	},
	{
		ID: FamilyQwen3Guard, Label: "Qwen3Guard",
		Description: "Qwen3Guard generative moderation model: Safe / Controversial / Unsafe with categories, for prompts and responses (multilingual).",
		Endpoint:    "chat",
		Hazards: []Hazard{
			{"violent", "Violent"}, {"non_violent_illegal", "Non-violent Illegal Acts"},
			{"sexual", "Sexual Content or Sexual Acts"}, {"pii", "PII"}, {"self_harm", "Suicide & Self-Harm"},
			{"unethical", "Unethical Acts"}, {"political", "Politically Sensitive Topics"},
			{"copyright", "Copyright Violation"}, {"jailbreak", "Jailbreak"},
		},
		DefaultHazards: []string{"violent", "non_violent_illegal", "sexual", "self_harm", "unethical", "jailbreak"},
		Phases:         []string{ModePre, ModePost},
	},
	{
		ID: FamilyShieldGemma, Label: "ShieldGemma",
		Description: "ShieldGemma policy classifier. Scores P(violation) per harm type from token probabilities; the custom policy text is checked as an extra principle.",
		Endpoint:    "completions",
		Hazards: []Hazard{
			{"dangerous_content", "Dangerous Content"}, {"harassment", "Harassment"},
			{"hate_speech", "Hate Speech"}, {"sexually_explicit", "Sexually Explicit Information"},
		},
		DefaultHazards:   []string{"dangerous_content", "harassment", "hate_speech", "sexually_explicit"},
		UsesThreshold:    true,
		DefaultThreshold: 0.5,
		Phases:           []string{ModePre, ModePost},
	},
	{
		ID: FamilyPromptGuard, Label: "Prompt Guard",
		Description:      "Prompt Guard sequence classifier (vLLM classify runner) for prompt injection and jailbreak attempts in user input and tool results.",
		Endpoint:         "classify",
		UsesThreshold:    true,
		DefaultThreshold: 0.5,
		Phases:           []string{ModePre},
	},
}

// FamilyInfo returns the catalog entry of a guard model family.
func FamilyInfo(id string) (FamilyMeta, bool) {
	for _, f := range familyCatalog {
		if f.ID == id {
			return cloneFamily(f), true
		}
	}
	return FamilyMeta{}, false
}

// AllFamilies lists every guard model family in display order.
func AllFamilies() []FamilyMeta {
	out := make([]FamilyMeta, len(familyCatalog))
	for i, f := range familyCatalog {
		out[i] = cloneFamily(f)
	}
	return out
}

func cloneFamily(f FamilyMeta) FamilyMeta {
	f.Hazards = slices.Clone(f.Hazards)
	f.DefaultHazards = slices.Clone(f.DefaultHazards)
	f.Phases = slices.Clone(f.Phases)
	return f
}

func (f FamilyMeta) hazardLabel(id string) string {
	for _, h := range f.Hazards {
		if h.ID == id {
			return h.Label
		}
	}
	return id
}

// guardModel is the compiled state of a guard_model rule.
type guardModel struct {
	meta      FamilyMeta
	hazards   []string // enabled hazard ids, in catalog order
	enabled   map[string]bool
	threshold float64
}

func init() {
	registerKind(KindGuardModel, kindImpl{validate: validateGuardModel, compile: compileGuardModel, check: checkGuardModel})
}

func validateGuardModel(c *Config) error {
	c.Family, c.Model = strings.TrimSpace(c.Family), strings.TrimSpace(c.Model)
	if c.Family == "" {
		return errors.New("choose the guard model family")
	}
	meta, ok := FamilyInfo(c.Family)
	if !ok {
		return fmt.Errorf("unknown guard model family %q", c.Family)
	}
	if c.Model == "" {
		return errors.New("choose the guard model")
	}
	c.Hazards = cleanList(c.Hazards)
	for _, h := range c.Hazards {
		if !slices.ContainsFunc(meta.Hazards, func(x Hazard) bool { return x.ID == h }) {
			if len(meta.Hazards) == 0 {
				return fmt.Errorf("%s has no selectable categories", meta.Label)
			}
			return fmt.Errorf("unknown %s category %q", meta.Label, h)
		}
	}
	if c.Threshold < 0 || c.Threshold > 1 {
		return errors.New("threshold must be between 0 and 1")
	}
	if c.TimeoutSeconds < 0 || c.TimeoutSeconds > 300 {
		return errors.New("timeout must be between 1 and 300 seconds")
	}
	return nil
}

func compileGuardModel(r *rule) error {
	c := r.g.Config
	meta, ok := FamilyInfo(c.Family)
	if !ok {
		return fmt.Errorf("unknown guard model family %q", c.Family)
	}
	want := c.Hazards
	if len(want) == 0 {
		want = meta.DefaultHazards
	}
	gm := &guardModel{meta: meta, enabled: map[string]bool{}, threshold: c.Threshold}
	for _, h := range meta.Hazards {
		if slices.Contains(want, h.ID) {
			gm.hazards = append(gm.hazards, h.ID)
			gm.enabled[h.ID] = true
		}
	}
	if gm.threshold <= 0 {
		gm.threshold = meta.DefaultThreshold
	}
	r.ext = gm
	return nil
}

func checkGuardModel(ctx context.Context, e *Engine, r *rule, in checkInput) finding {
	gm, _ := r.ext.(*guardModel)
	if gm == nil {
		return finding{err: errors.New("guard model not compiled")}
	}
	conv := buildConversation(in)
	if !hasText(conv) {
		return finding{}
	}
	u, err := resolveUpstream(e, r.g.Config.Model)
	if err != nil {
		return finding{err: err}
	}
	ctx, cancel := context.WithTimeout(ctx, modelTimeout(r.g.Config))
	defer cancel()
	call := guardCall{e: e, u: u, gm: gm, cfg: r.g.Config, phase: in.phase, conv: conv, in: in}
	switch gm.meta.ID {
	case FamilyLlamaGuard:
		return call.llamaGuard(ctx)
	case FamilyGraniteGuardian:
		return call.graniteGuardian(ctx)
	case FamilyQwen3Guard:
		return call.qwen3Guard(ctx)
	case FamilyShieldGemma:
		return call.shieldGemma(ctx)
	case FamilyPromptGuard:
		return call.promptGuard(ctx)
	}
	return finding{err: fmt.Errorf("unsupported guard model family %q", gm.meta.ID)}
}

// guardCall carries one check's inputs to a family adapter.
type guardCall struct {
	e     *Engine
	u     *upstream
	gm    *guardModel
	cfg   Config
	phase string
	conv  []turn
	in    checkInput
}

// flagged builds the finding for a positive verdict. labels are category names
// (never user content).
func (g guardCall) flagged(labels []string) finding {
	detail := "unsafe"
	reason := "flagged as unsafe by a safety model"
	if len(labels) > 0 {
		detail = "unsafe: " + strings.Join(labels, ", ")
		reason += " (" + strings.Join(labels, ", ") + ")"
	}
	return finding{hit: true, detail: detail, reason: reason}
}

// --- conversation building ---

// turn is one conversation message reduced to plain text.
type turn struct {
	Role    string // system | user | assistant | tool
	Content string
}

// convMaxChars bounds the conversation sent to a guard model (latest turns win).
const convMaxChars = 16000

// buildConversation assembles the conversation a guard model judges:
//   - pre: the request's chat messages, or the request text as one user turn;
//   - post: the forwarded request's messages (when known) plus the assistant
//     response text from the segments.
func buildConversation(in checkInput) []turn {
	var ts []turn
	if in.phase == ModePost {
		if in.info != nil && in.info.Request != nil {
			ts = requestTurns(in.info.Request)
		}
		if resp := joinSegments(in.segs); strings.TrimSpace(resp) != "" {
			ts = append(ts, turn{Role: "assistant", Content: resp})
		}
	} else {
		if in.body != nil {
			ts, _ = messagesTurns(in.body)
		}
		if !hasText(ts) {
			ts = nil
			if txt := joinSegments(in.segs); strings.TrimSpace(txt) != "" {
				ts = []turn{{Role: "user", Content: txt}}
			}
		}
	}
	return boundTurns(ts, convMaxChars)
}

// requestTurns converts a request body to turns: chat messages, or the request
// text (prompt / input) as a single user turn.
func requestTurns(body map[string]any) []turn {
	if ts, ok := messagesTurns(body); ok && hasText(ts) {
		return ts
	}
	if txt := joinSegments(requestSegments(body)); strings.TrimSpace(txt) != "" {
		return []turn{{Role: "user", Content: txt}}
	}
	return nil
}

// messagesTurns reads body["messages"], keeping text parts only.
func messagesTurns(body map[string]any) ([]turn, bool) {
	msgs, ok := body["messages"].([]any)
	if !ok {
		return nil, false
	}
	var ts []turn
	for _, m := range msgs {
		mm, ok := m.(map[string]any)
		if !ok {
			continue
		}
		role, _ := mm["role"].(string)
		switch role {
		case "system", "developer":
			role = "system"
		case "user", "assistant":
		case "tool", "function":
			role = "tool"
		default:
			continue
		}
		txt := joinSegments(appendContent(nil, mm, "content"))
		if strings.TrimSpace(txt) == "" {
			continue
		}
		ts = append(ts, turn{Role: role, Content: txt})
	}
	return ts, true
}

func hasText(ts []turn) bool {
	for _, t := range ts {
		if strings.TrimSpace(t.Content) != "" {
			return true
		}
	}
	return false
}

// boundTurns keeps the latest turns within max runes. A turn that does not fit is
// shortened to its head and tail and becomes the oldest kept turn.
func boundTurns(ts []turn, limit int) []turn {
	budget := limit
	start := len(ts)
	var cut *turn
	for i := len(ts) - 1; i >= 0; i-- {
		n := utf8.RuneCountInString(ts[i].Content)
		if n <= budget {
			budget -= n
			start = i
			continue
		}
		if budget >= 200 || i == len(ts)-1 {
			t := ts[i]
			t.Content = headTail(t.Content, max(budget, 200))
			cut = &t
		}
		break
	}
	out := make([]turn, 0, len(ts)-start+1)
	if cut != nil {
		out = append(out, *cut)
	}
	return append(out, ts[start:]...)
}

// headTail shortens s to about n runes, keeping its beginning and end.
func headTail(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	h := n / 2
	return string(r[:h]) + "\n…\n" + string(r[len(r)-(n-h):])
}

// alternating reshapes turns for chat templates that require strictly alternating
// user/assistant messages starting with a user turn. System and tool turns are
// dropped (they are operator / tool content), unless nothing else is present;
// consecutive turns of one role are merged.
func alternating(ts []turn) []chatMessage {
	var out []chatMessage
	for _, t := range ts {
		if t.Role != "user" && t.Role != "assistant" {
			continue
		}
		if n := len(out); n > 0 && out[n-1].Role == t.Role {
			out[n-1].Content += "\n\n" + t.Content
			continue
		}
		if len(out) == 0 && t.Role == "assistant" {
			out = append(out, chatMessage{Role: "user", Content: ""})
		}
		out = append(out, chatMessage{Role: t.Role, Content: t.Content})
	}
	if len(out) == 0 {
		var parts []string
		for _, t := range ts {
			parts = append(parts, t.Content)
		}
		if txt := strings.Join(parts, "\n\n"); strings.TrimSpace(txt) != "" {
			out = []chatMessage{{Role: "user", Content: txt}}
		}
	}
	return out
}

// lastExchange returns the latest user text and, for post checks, the assistant
// response being judged.
func lastExchange(ts []turn, phase string) (user, assistant string) {
	msgs := alternating(ts)
	if len(msgs) == 0 {
		return "", ""
	}
	last := msgs[len(msgs)-1]
	if phase == ModePost && last.Role == "assistant" {
		if len(msgs) >= 2 {
			user = msgs[len(msgs)-2].Content
		}
		return user, last.Content
	}
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role == "user" {
			return msgs[i].Content, ""
		}
	}
	return "", ""
}
