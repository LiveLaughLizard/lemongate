package guardrails

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Prompt Guard: a sequence classifier served by vLLM's classify (pooling) runner.
// Text is chunked and sent in one POST {root}/classify request:
//
//	{"model": "<upstream>", "input": ["chunk", ...], "truncate_prompt_tokens": 512}
//
// Each data[] item has probs over the model's classes; class 0 is benign in both
// the 2-class (benign / malicious) and 3-class (benign / injection / jailbreak)
// variants. score = 1 − P(benign), max over chunks.

const (
	promptGuardChunk    = 2000  // characters per chunk
	promptGuardOverlap  = 200   // characters shared by neighbouring chunks
	promptGuardMaxChars = 32000 // latest characters classified
)

type classifyResponse struct {
	Data []struct {
		Index      int       `json:"index"`
		Label      string    `json:"label"`
		Probs      []float64 `json:"probs"`
		NumClasses int       `json:"num_classes"`
	} `json:"data"`
}

func (g guardCall) promptGuard(ctx context.Context) finding {
	text := g.promptGuardText()
	if strings.TrimSpace(text) == "" {
		return finding{}
	}
	chunks := chunkText(text, promptGuardChunk, promptGuardOverlap)
	body := map[string]any{"model": g.u.model, "input": chunks, "truncate_prompt_tokens": 512}
	var out classifyResponse
	if err := g.e.postJSON(ctx, g.u, g.u.root("/classify"), body, &out); err != nil {
		return finding{err: err}
	}
	score, label, err := promptGuardScore(out)
	if err != nil {
		return finding{err: err}
	}
	detail := fmt.Sprintf("%s %.2f", label, score)
	if score < g.gm.threshold {
		return finding{detail: detail}
	}
	return finding{hit: true, detail: detail,
		reason: fmt.Sprintf("possible prompt injection or jailbreak (%s %.2f)", label, score)}
}

// promptGuardText selects what the classifier sees: in pre, the newest turn of the
// conversation (user messages and tool results after the last assistant message);
// in post, the response text.
func (g guardCall) promptGuardText() string {
	var parts []string
	if g.phase == ModePost {
		parts = append(parts, joinSegments(g.in.segs))
	} else {
		var ts []turn
		if g.in.body != nil {
			ts, _ = messagesTurns(g.in.body)
		}
		last := -1
		for i, t := range ts {
			if t.Role == "assistant" {
				last = i
			}
		}
		for _, t := range ts[last+1:] {
			if t.Role == "user" || t.Role == "tool" {
				parts = append(parts, t.Content)
			}
		}
		if len(parts) == 0 {
			parts = append(parts, joinSegments(g.in.segs))
		}
	}
	text := strings.Join(parts, "\n")
	if r := []rune(text); len(r) > promptGuardMaxChars {
		text = string(r[len(r)-promptGuardMaxChars:])
	}
	return text
}

// chunkText splits text into rune windows of size with overlap between neighbours.
func chunkText(text string, size, overlap int) []string {
	r := []rune(text)
	if len(r) <= size {
		return []string{text}
	}
	step := size - overlap
	var out []string
	for i := 0; i < len(r); i += step {
		end := min(i+size, len(r))
		out = append(out, string(r[i:end]))
		if end == len(r) {
			break
		}
	}
	return out
}

// promptGuardScore returns the highest non-benign probability over all chunks and
// the label of the most likely non-benign class.
func promptGuardScore(out classifyResponse) (float64, string, error) {
	if len(out.Data) == 0 {
		return 0, "", errors.New("classifier returned no results")
	}
	best, label := -1.0, ""
	for _, d := range out.Data {
		if len(d.Probs) < 2 {
			return 0, "", errors.New("classifier returned no class probabilities")
		}
		score := 1 - d.Probs[0]
		top := 1
		for i := 2; i < len(d.Probs); i++ {
			if d.Probs[i] > d.Probs[top] {
				top = i
			}
		}
		if score > best {
			best, label = score, promptGuardLabel(len(d.Probs), top, d.Label)
		}
	}
	return clamp01(best), label, nil
}

// promptGuardLabel names a non-benign class index.
func promptGuardLabel(numClasses, idx int, served string) string {
	s := strings.ToLower(strings.TrimSpace(served))
	if s != "" && s != "benign" && !strings.HasPrefix(s, "label_") {
		return s // e.g. "injection" / "jailbreak" / "malicious" from the model config
	}
	if numClasses == 2 {
		return "malicious"
	}
	switch idx {
	case 1:
		return "injection"
	case 2:
		return "jailbreak"
	}
	return fmt.Sprintf("class_%d", idx)
}

func clamp01(x float64) float64 { return max(0, min(1, x)) }
