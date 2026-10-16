package guardrails

import (
	"context"
	"errors"
	"strings"
)

// Qwen3Guard (generative): the conversation goes to /v1/chat/completions and the
// model's chat template builds the moderation prompt (prompt moderation when the
// last turn is the user's, response moderation when it is the assistant's).
// Output:
//
//	Safety: Safe|Unsafe|Controversial
//	Categories: Violent, Jailbreak        (or "None")
//	Refusal: Yes|No                       (responses only)

type qwenVerdict struct {
	safety  string // safe | unsafe | controversial
	cats    []string
	unknown []string // category labels that did not map to a hazard id
	refusal string   // "", "yes" or "no"
}

func (g guardCall) qwen3Guard(ctx context.Context) finding {
	out, err := g.e.chatCompletion(ctx, g.u, alternating(g.conv), nil, 64)
	if err != nil {
		return finding{err: err}
	}
	v, err := parseQwen3Guard(out)
	if err != nil {
		return finding{err: err}
	}
	detail := v.safety
	if len(v.cats) > 0 {
		detail += ": " + strings.Join(v.cats, ", ")
	}
	if v.refusal != "" {
		detail += "; refusal: " + v.refusal
	}
	flag := v.safety == "unsafe" || (v.safety == "controversial" && g.cfg.StrictControversial)
	if !flag {
		return finding{detail: detail}
	}
	if len(v.cats) == 0 {
		f := g.flagged(nil)
		f.detail = detail
		return f
	}
	var labels []string
	for _, c := range v.cats {
		if g.gm.enabled[c] {
			labels = append(labels, g.gm.meta.hazardLabel(c))
		}
	}
	if len(labels) == 0 {
		return finding{detail: detail + " (categories not enabled)"}
	}
	f := g.flagged(labels)
	f.detail = v.safety + ": " + strings.Join(labels, ", ")
	if v.refusal != "" {
		f.detail += "; refusal: " + v.refusal
	}
	return f
}

// qwenCategory maps a Qwen3Guard category label to a hazard id.
func qwenCategory(label string) (string, bool) {
	l := strings.ToLower(strings.TrimSpace(label))
	switch {
	case l == "" || l == "none":
		return "", false
	case strings.HasPrefix(l, "non-violent") || strings.HasPrefix(l, "non violent") || strings.Contains(l, "illegal"):
		return "non_violent_illegal", true
	case strings.HasPrefix(l, "violen"):
		return "violent", true
	case strings.HasPrefix(l, "sexual"):
		return "sexual", true
	case l == "pii" || strings.Contains(l, "personal"):
		return "pii", true
	case strings.Contains(l, "suicide") || strings.Contains(l, "self-harm") || strings.Contains(l, "self harm"):
		return "self_harm", true
	case strings.HasPrefix(l, "unethical"):
		return "unethical", true
	case strings.HasPrefix(l, "politic"):
		return "political", true
	case strings.HasPrefix(l, "copyright"):
		return "copyright", true
	case strings.HasPrefix(l, "jailbreak"):
		return "jailbreak", true
	}
	return "", false
}

// parseQwen3Guard reads the "Safety:", "Categories:" and "Refusal:" lines.
func parseQwen3Guard(s string) (qwenVerdict, error) {
	var v qwenVerdict
	for _, line := range strings.Split(stripThink(s), "\n") {
		k, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch strings.ToLower(strings.Trim(strings.TrimSpace(k), "*")) {
		case "safety":
			v.safety = strings.ToLower(strings.Trim(val, "*. "))
		case "categories", "category":
			seen := map[string]bool{}
			for _, c := range strings.Split(val, ",") {
				id, ok := qwenCategory(c)
				switch {
				case ok && !seen[id]:
					seen[id] = true
					v.cats = append(v.cats, id)
				case !ok && strings.TrimSpace(c) != "" && !strings.EqualFold(strings.TrimSpace(c), "none"):
					v.unknown = append(v.unknown, strings.TrimSpace(c))
				}
			}
		case "refusal":
			v.refusal = strings.ToLower(strings.Trim(val, "*. "))
		}
	}
	switch v.safety {
	case "safe", "unsafe", "controversial":
		return v, nil
	case "":
		return v, errors.New("guard model verdict has no Safety line")
	}
	return v, errors.New("guard model verdict not recognized")
}
