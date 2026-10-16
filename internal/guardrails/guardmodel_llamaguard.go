package guardrails

import (
	"context"
	"errors"
	"regexp"
	"strings"
)

// Llama Guard 3 / 4: the conversation goes to /v1/chat/completions unchanged and the
// model's own chat template builds the safety prompt. Disabled categories are
// removed from that prompt with chat_template_kwargs.excluded_category_keys.
// Output: "safe", or "unsafe" followed by a line of codes such as "S1,S10".

func (g guardCall) llamaGuard(ctx context.Context) finding {
	msgs := alternating(g.conv)
	var excluded []string
	for _, h := range g.gm.meta.Hazards {
		if !g.gm.enabled[h.ID] {
			excluded = append(excluded, h.ID)
		}
	}
	kw := map[string]any{"excluded_category_keys": nonNil(excluded)}
	out, err := g.e.chatCompletion(ctx, g.u, msgs, kw, 20)
	if err != nil {
		return finding{err: err}
	}
	unsafe, cats, err := parseLlamaGuard(out)
	if err != nil {
		return finding{err: err}
	}
	if !unsafe {
		return finding{detail: "safe"}
	}
	if len(cats) == 0 {
		return g.flagged(nil)
	}
	var labels []string
	for _, c := range cats {
		if g.gm.enabled[c] {
			labels = append(labels, c+" "+g.gm.meta.hazardLabel(c))
		}
	}
	if len(labels) == 0 {
		return finding{detail: "unsafe only in disabled categories: " + strings.Join(cats, ",")}
	}
	return g.flagged(labels)
}

var llamaGuardCodeRe = regexp.MustCompile(`(?i)\bS(\d{1,2})\b`)

// parseLlamaGuard reads a Llama Guard verdict: the first non-empty line is
// "safe" or "unsafe"; for unsafe, following lines list category codes.
func parseLlamaGuard(s string) (unsafe bool, cats []string, err error) {
	lines := strings.Split(strings.TrimSpace(stripThink(s)), "\n")
	first := -1
	for i, l := range lines {
		if strings.TrimSpace(l) != "" {
			first = i
			break
		}
	}
	if first < 0 {
		return false, nil, errors.New("guard model returned an empty verdict")
	}
	head := strings.ToLower(strings.Trim(strings.TrimSpace(lines[first]), ".:*` "))
	switch {
	case head == "safe":
		return false, nil, nil
	case strings.HasPrefix(head, "unsafe"):
		unsafe = true
	case strings.HasPrefix(head, "safe"):
		return false, nil, nil
	default:
		return false, nil, errors.New("guard model verdict not recognized")
	}
	seen := map[string]bool{}
	tail := lines[first]
	if i := strings.Index(strings.ToLower(tail), "unsafe"); i >= 0 {
		tail = tail[i+len("unsafe"):]
	}
	rest := strings.Join(append([]string{tail}, lines[first+1:]...), "\n")
	for _, m := range llamaGuardCodeRe.FindAllStringSubmatch(rest, -1) {
		code := "S" + strings.TrimLeft(m[1], "0")
		if !seen[code] {
			seen[code] = true
			cats = append(cats, code)
		}
	}
	return true, cats, nil
}

func nonNil(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}
