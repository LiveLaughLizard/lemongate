package guardrails

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
)

// Granite Guardian: one /v1/chat/completions call per enabled risk, in parallel,
// with chat_template_kwargs.guardian_config.risk_name selecting the risk. The
// template judges the last user turn (pre) or the assistant turn (post).
// Output: "Yes" (risk present) / "No", or "<score> yes </score>" in newer
// versions, possibly after a "<think>…</think>" block.

// graniteUserOnly lists risks defined on the user prompt only.
var graniteUserOnly = map[string]bool{"jailbreak": true}

func (g guardCall) graniteGuardian(ctx context.Context) finding {
	user, assistant := lastExchange(g.conv, g.phase)
	msgs := []chatMessage{{Role: "user", Content: user}}
	if g.phase == ModePost {
		msgs = append(msgs, chatMessage{Role: "assistant", Content: assistant})
	}
	var risks []string
	for _, h := range g.gm.hazards {
		if g.phase == ModePost && graniteUserOnly[h] {
			continue
		}
		risks = append(risks, h)
	}
	if len(risks) == 0 {
		return finding{detail: "no risks apply to this phase"}
	}
	type res struct {
		yes bool
		err error
	}
	results := make([]res, len(risks))
	var wg sync.WaitGroup
	for i, risk := range risks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			kw := map[string]any{"guardian_config": map[string]any{"risk_name": risk}}
			out, err := g.e.chatCompletion(ctx, g.u, msgs, kw, 32)
			if err != nil {
				results[i] = res{err: err}
				return
			}
			yes, err := parseGraniteGuardian(out)
			results[i] = res{yes: yes, err: err}
		}()
	}
	wg.Wait()
	var labels []string
	var firstErr error
	for i, r := range results {
		if r.err != nil && firstErr == nil {
			firstErr = r.err
		}
		if r.yes {
			labels = append(labels, g.gm.meta.hazardLabel(risks[i]))
		}
	}
	if len(labels) > 0 {
		return g.flagged(labels)
	}
	if firstErr != nil {
		return finding{err: firstErr}
	}
	return finding{detail: "no risk detected"}
}

var graniteScoreRe = regexp.MustCompile(`(?is)<score>\s*(\w+)\s*</score>`)

// parseGraniteGuardian reports whether the model answered "Yes" (risk present).
func parseGraniteGuardian(s string) (bool, error) {
	if m := graniteScoreRe.FindAllStringSubmatch(s, -1); len(m) > 0 {
		return yesNo(m[len(m)-1][1])
	}
	s = strings.TrimSpace(stripThink(s))
	if s == "" {
		return false, errors.New("guard model returned an empty verdict")
	}
	word := strings.FieldsFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z')
	})
	if len(word) == 0 {
		return false, errors.New("guard model verdict not recognized")
	}
	return yesNo(word[0])
}

func yesNo(w string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(w)) {
	case "yes":
		return true, nil
	case "no":
		return false, nil
	}
	return false, errors.New("guard model verdict not recognized")
}
