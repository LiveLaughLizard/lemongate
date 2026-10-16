package guardrails

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
)

// ShieldGemma: one raw-prompt /v1/completions call per enabled harm type (plus
// Config.Policy as a custom principle), using the documented prompt format with
// max_tokens 1 and logprobs 20. P(Yes) is the softmax over the "Yes" / "No"
// candidates found among the top log-probabilities of the first token.

// shieldGemmaHarms holds the guideline of each harm type, worded after the
// subject ("The prompt shall not …" / "The chatbot shall not …").
var shieldGemmaHarms = map[string]struct{ name, prompt, response string }{
	"dangerous_content": {"No Dangerous Content",
		"contain or seek generation of content that harming oneself and/or others (e.g., accessing or building firearms and explosive devices, promotion of terrorism, instructions for suicide).",
		"generate content that harming oneself and/or others (e.g., accessing or building firearms and explosive devices, promotion of terrorism, instructions for suicide)."},
	"harassment": {"No Harassment",
		"contain or seek generation of content that is malicious, intimidating, bullying, or abusive content targeting another individual (e.g., physical threats, denial of tragic events, disparaging victims of violence).",
		"generate content that is malicious, intimidating, bullying, or abusive content targeting another individual (e.g., physical threats, denial of tragic events, disparaging victims of violence)."},
	"hate_speech": {"No Hate Speech",
		"contain or seek generation of content that targeting identity and/or protected attributes (e.g., racial slurs, promotion of discrimination, calls to violence against protected groups) or dehumanizing/belittling/vilifying on the bases of race, ethnicity, religion, disability, age, nationality, veteran status, sexual orientation, gender, gender identity, caste, or any other protected status. We do allow content that includes a reference to a protected individual or group in a positive manner.",
		"generate content that targeting identity and/or protected attributes (e.g., racial slurs, promotion of discrimination, calls to violence against protected groups) or dehumanizing/belittling/vilifying on the bases of race, ethnicity, religion, disability, age, nationality, veteran status, sexual orientation, gender, gender identity, caste, or any other protected status. We do allow content that includes a reference to a protected individual or group in a positive manner."},
	"sexually_explicit": {"No Sexually Explicit Information",
		"contain or seek generation of content that contains references to sexual acts or other lewd content (e.g., sexually graphic descriptions, content aimed at causing arousal). Medical or scientific terms related to human anatomy or sex education are permitted.",
		"generate content that contains references to sexual acts or other lewd content (e.g., sexually graphic descriptions, content aimed at causing arousal). Medical or scientific terms related to human anatomy or sex education are permitted."},
}

// shieldGemmaPrinciple returns the "* …" principle line for a harm type.
func shieldGemmaPrinciple(harm, phase string) string {
	h := shieldGemmaHarms[harm]
	if phase == ModePost {
		return fmt.Sprintf("%q: The chatbot shall not %s", h.name, h.response)
	}
	return fmt.Sprintf("%q: The prompt shall not %s", h.name, h.prompt)
}

// shieldGemmaPrompt builds the documented classification prompt.
func shieldGemmaPrompt(user, response, principle, phase string) string {
	var b strings.Builder
	if phase == ModePost {
		b.WriteString("You are a policy expert trying to help determine whether an AI response to prompt is in\nviolation of the defined safety policies.\n\n")
		b.WriteString("<start_of_turn>\nHuman Question: " + strings.TrimSpace(user) + "\n<end_of_turn>\n\n")
		b.WriteString("<start_of_turn>\nChatbot Response: " + strings.TrimSpace(response) + "\n<end_of_turn>\n\n")
		b.WriteString("Our safety principle is defined in the below:\n\n* " + principle + "\n\n")
		b.WriteString("Does the Chatbot Response violate the above principle? Your answer must start\nwith 'Yes' or 'No'. And then walk through step by step to be sure we answer\ncorrectly.\n")
		return b.String()
	}
	b.WriteString("You are a policy expert trying to help determine whether a user\nprompt is in violation of the defined safety policies.\n\n")
	b.WriteString("<start_of_turn>\nHuman Question: " + strings.TrimSpace(user) + "\n<end_of_turn>\n\n")
	b.WriteString("Our safety principle is defined in the below:\n\n* " + principle + "\n\n")
	b.WriteString("Does the human question violate the above principle? Your answer must start\nwith 'Yes' or 'No'. And then walk through step by step to be sure we answer\ncorrectly.\n")
	return b.String()
}

func (g guardCall) shieldGemma(ctx context.Context) finding {
	user, response := lastExchange(g.conv, g.phase)
	type check struct{ id, label, principle string }
	var checks []check
	for _, h := range g.gm.hazards {
		checks = append(checks, check{h, g.gm.meta.hazardLabel(h), shieldGemmaPrinciple(h, g.phase)})
	}
	if p := strings.TrimSpace(g.cfg.Policy); p != "" {
		checks = append(checks, check{"custom", "Custom policy", p})
	}
	if len(checks) == 0 {
		return finding{detail: "no harm types enabled"}
	}
	type res struct {
		p   float64
		err error
	}
	results := make([]res, len(checks))
	var wg sync.WaitGroup
	for i, c := range checks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := g.shieldGemmaScore(ctx, shieldGemmaPrompt(user, response, c.principle, g.phase))
			results[i] = res{p, err}
		}()
	}
	wg.Wait()
	var hits, scores []string
	var firstErr error
	for i, r := range results {
		if r.err != nil {
			if firstErr == nil {
				firstErr = r.err
			}
			continue
		}
		s := fmt.Sprintf("%s %.2f", checks[i].label, r.p)
		scores = append(scores, s)
		if r.p >= g.gm.threshold {
			hits = append(hits, s)
		}
	}
	if len(hits) > 0 {
		f := g.flagged(hits)
		return f
	}
	if firstErr != nil {
		return finding{err: firstErr}
	}
	return finding{detail: "scores: " + strings.Join(scores, ", ")}
}

func (g guardCall) shieldGemmaScore(ctx context.Context, prompt string) (float64, error) {
	body := map[string]any{
		"model":       g.u.model,
		"prompt":      prompt,
		"max_tokens":  1,
		"logprobs":    20,
		"temperature": 0,
		"stream":      false,
	}
	var out completionLogprobs
	if err := g.e.postJSON(ctx, g.u, g.u.v1("/completions"), body, &out); err != nil {
		return 0, err
	}
	return out.pYes()
}

// completionLogprobs is the subset of a /v1/completions response with logprobs.
type completionLogprobs struct {
	Choices []struct {
		Text     string `json:"text"`
		Logprobs *struct {
			Tokens      []string             `json:"tokens"`
			TopLogprobs []map[string]float64 `json:"top_logprobs"`
		} `json:"logprobs"`
	} `json:"choices"`
}

// pYes computes P(Yes) from the first token's top log-probabilities, falling back
// to the generated text when neither candidate is present.
func (c completionLogprobs) pYes() (float64, error) {
	if len(c.Choices) == 0 {
		return 0, errors.New("guard model returned no choices")
	}
	ch := c.Choices[0]
	if ch.Logprobs != nil && len(ch.Logprobs.TopLogprobs) > 0 {
		if p, ok := yesProbability(ch.Logprobs.TopLogprobs[0]); ok {
			return p, nil
		}
	}
	text := ch.Text
	if text == "" && ch.Logprobs != nil && len(ch.Logprobs.Tokens) > 0 {
		text = ch.Logprobs.Tokens[0]
	}
	yes, err := yesNo(strings.Trim(text, " \t\n▁Ġ"))
	if err != nil {
		return 0, err
	}
	if yes {
		return 1, nil
	}
	return 0, nil
}

// yesProbability is the softmax over the Yes / No candidates (any casing or
// leading-space token variant) in a top-logprobs map.
func yesProbability(top map[string]float64) (float64, bool) {
	var yes, no []float64
	keys := make([]string, 0, len(top))
	for k := range top {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch strings.ToLower(strings.Trim(k, " \t\n▁Ġ")) {
		case "yes":
			yes = append(yes, top[k])
		case "no":
			no = append(no, top[k])
		}
	}
	if len(yes) == 0 && len(no) == 0 {
		return 0, false
	}
	// log-sum-exp per side, then a two-way softmax.
	ly, ln := logSumExp(yes), logSumExp(no)
	if math.IsInf(ln, -1) {
		return 1, true
	}
	if math.IsInf(ly, -1) {
		return 0, true
	}
	m := math.Max(ly, ln)
	ey, en := math.Exp(ly-m), math.Exp(ln-m)
	return ey / (ey + en), true
}

func logSumExp(xs []float64) float64 {
	if len(xs) == 0 {
		return math.Inf(-1)
	}
	m := xs[0]
	for _, x := range xs[1:] {
		m = math.Max(m, x)
	}
	if math.IsInf(m, -1) {
		return m
	}
	s := 0.0
	for _, x := range xs {
		s += math.Exp(x - m)
	}
	return m + math.Log(s)
}
