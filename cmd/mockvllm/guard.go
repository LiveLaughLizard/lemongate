package main

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// Deterministic guard-model behaviours (see the package comment for triggers).

type guardMsg struct {
	Role    string
	Content string
}

// guardFamily maps a served model id to a guard family ("" for ordinary models).
func guardFamily(model string) string {
	m := strings.ToLower(model)
	for _, f := range []string{"llama-guard", "granite-guardian", "qwen3guard", "shieldgemma", "prompt-guard"} {
		if strings.Contains(m, f) {
			return f
		}
	}
	return ""
}

// trigger is what one trigger means for each family.
type trigger struct {
	words     []string // lower-case word prefixes
	exact     string   // case-sensitive substring
	phrase    *regexp.Regexp
	llama     string   // S-code
	granite   []string // risk names
	qwen      string   // category label
	shield    []string // harm ids; "*" = every principle
	jailbreak bool
}

// injectionRe matches "ignore previous instructions", "ignore all previous instructions", ...
var injectionRe = regexp.MustCompile(`ignore (all |the |any )*(previous|prior) instructions`)

var triggers = []trigger{
	{words: []string{"kill"}, llama: "S1", granite: []string{"violence", "harm"}, qwen: "Violent", shield: []string{"dangerous_content"}},
	{words: []string{"bomb"}, llama: "S9", granite: []string{"violence", "harm"}, qwen: "Violent", shield: []string{"dangerous_content"}},
	{words: []string{"hate"}, llama: "S10", granite: []string{"social_bias", "harm"}, qwen: "Unethical Acts", shield: []string{"hate_speech"}},
	{words: []string{"nsfw"}, llama: "S12", granite: []string{"sexual_content", "harm"}, qwen: "Sexual Content or Sexual Acts", shield: []string{"sexually_explicit"}},
	{exact: "UNSAFE", llama: "S1", granite: []string{"harm"}, qwen: "Violent", shield: []string{"*"}},
	{words: []string{"jailbreak"}, granite: []string{"jailbreak"}, qwen: "Jailbreak", jailbreak: true},
	{phrase: injectionRe, granite: []string{"jailbreak"}, qwen: "Jailbreak", jailbreak: true},
}

func words(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
}

// matchedTriggers returns the triggers present in text.
func matchedTriggers(text string) []trigger {
	ws := words(text)
	lower := strings.ToLower(text)
	var out []trigger
	for _, t := range triggers {
		hit := t.exact != "" && strings.Contains(text, t.exact) || t.phrase != nil && t.phrase.MatchString(lower)
		for _, p := range t.words {
			for _, w := range ws {
				if strings.HasPrefix(w, p) {
					hit = true
				}
			}
		}
		if hit {
			out = append(out, t)
		}
	}
	return out
}

func lastMsg(msgs []guardMsg) guardMsg {
	if len(msgs) == 0 {
		return guardMsg{}
	}
	return msgs[len(msgs)-1]
}

// guardChat produces a chat-family guard verdict.
func guardChat(family, model string, msgs []guardMsg, kw map[string]any) (string, bool) {
	last := lastMsg(msgs)
	trigs := matchedTriggers(last.Content)
	switch family {
	case "llama-guard":
		excluded := map[string]bool{}
		if xs, ok := kw["excluded_category_keys"].([]any); ok {
			for _, x := range xs {
				excluded[fmt.Sprint(x)] = true
			}
		}
		var codes []string
		for _, t := range trigs {
			if t.llama != "" && !excluded[t.llama] && !contains(codes, t.llama) {
				codes = append(codes, t.llama)
			}
		}
		if len(codes) == 0 {
			return "\n\nsafe", true
		}
		return "\n\nunsafe\n" + strings.Join(codes, ","), true
	case "granite-guardian":
		risk := "harm"
		if gc, ok := kw["guardian_config"].(map[string]any); ok {
			if r, ok := gc["risk_name"].(string); ok && r != "" {
				risk = r
			}
		}
		yes := false
		for _, t := range trigs {
			if contains(t.granite, risk) && (!t.jailbreak || last.Role == "user") {
				yes = true
			}
		}
		if strings.Contains(strings.ToLower(model), "3.3") {
			if yes {
				return "<think>The text is risky.</think>\n<score> yes </score>", true
			}
			return "<think>Nothing risky.</think>\n<score> no </score>", true
		}
		if yes {
			return "Yes", true
		}
		return "No", true
	case "qwen3guard":
		response := last.Role == "assistant"
		var cats []string
		for _, t := range trigs {
			if t.qwen != "" && (!t.jailbreak || !response) && !contains(cats, t.qwen) {
				cats = append(cats, t.qwen)
			}
		}
		safety := "Unsafe"
		if len(cats) == 0 {
			safety, cats = "Safe", []string{"None"}
			if strings.Contains(last.Content, "CONTROVERSIAL") {
				safety, cats = "Controversial", []string{"Politically Sensitive Topics"}
			}
		}
		out := "Safety: " + safety + "\nCategories: " + strings.Join(cats, ", ")
		if response {
			refusal := "No"
			l := strings.ToLower(last.Content)
			if strings.Contains(l, "i can't") || strings.Contains(l, "i cannot") || strings.Contains(l, "sorry") {
				refusal = "Yes"
			}
			out += "\nRefusal: " + refusal
		}
		return out, true
	}
	return "", false
}

// shieldGemmaCompletion answers a ShieldGemma prompt with "Yes"/"No" and, when
// requested, OpenAI-style completion logprobs for the first token.
func shieldGemmaCompletion(prompt string, logprobs *int) (string, any) {
	judged := between(prompt, "Human Question:", "<end_of_turn>")
	if strings.Contains(prompt, "Chatbot Response:") {
		judged = between(prompt, "Chatbot Response:", "<end_of_turn>")
	}
	principle := between(prompt, "* ", "\n\nDoes")
	harm := "custom"
	for id, needle := range map[string]string{"dangerous_content": "Dangerous Content", "harassment": "Harassment",
		"hate_speech": "Hate Speech", "sexually_explicit": "Sexually Explicit"} {
		if strings.Contains(principle, needle) {
			harm = id
		}
	}
	yes := false
	for _, t := range matchedTriggers(judged) {
		if contains(t.shield, "*") || contains(t.shield, harm) {
			yes = true
		}
	}
	py, pn := 0.02, 0.97
	tok := "No"
	if yes {
		py, pn, tok = 0.93, 0.05, "Yes"
	}
	if logprobs == nil {
		return tok, nil
	}
	lp := map[string]float64{"Yes": math.Log(py), "No": math.Log(pn), "The": math.Log(0.005), "**": math.Log(0.003)}
	return tok, map[string]any{"tokens": []string{tok}, "token_logprobs": []float64{lp[tok]},
		"top_logprobs": []any{lp}, "text_offset": []int{0}}
}

func between(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}
	s = s[i+len(start):]
	if j := strings.Index(s, end); j >= 0 {
		s = s[:j]
	}
	return strings.TrimSpace(s)
}

// classify imitates vLLM's POST /classify (pooling runner) for prompt-guard ids.
func classify(served []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Model string `json:"model"`
			Input any    `json:"input"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]any{"object": "error", "message": "invalid JSON", "type": "BadRequestError", "code": 400})
			return
		}
		if !checkModel(w, served, req.Model) {
			return
		}
		var inputs []string
		switch v := req.Input.(type) {
		case string:
			inputs = []string{v}
		case []any:
			for _, x := range v {
				inputs = append(inputs, fmt.Sprint(x))
			}
		}
		twoClass := strings.Contains(strings.ToLower(req.Model), "prompt-guard-2")
		var data []any
		pt := 0
		for i, in := range inputs {
			pt += countTokens(in)
			labels, probs := promptGuardProbs(in, twoClass)
			top := 0
			for j := range probs {
				if probs[j] > probs[top] {
					top = j
				}
			}
			data = append(data, map[string]any{"index": i, "label": labels[top], "probs": probs, "num_classes": len(probs)})
		}
		writeJSON(w, 200, map[string]any{"id": fmt.Sprintf("classify-%d", time.Now().UnixNano()), "object": "list",
			"created": time.Now().Unix(), "model": req.Model, "data": data,
			"usage": map[string]any{"prompt_tokens": pt, "total_tokens": pt, "completion_tokens": 0}})
	}
}

func promptGuardProbs(text string, twoClass bool) ([]string, []float64) {
	lower := strings.ToLower(text)
	jb := strings.Contains(lower, "jailbreak")
	inj := injectionRe.MatchString(lower)
	if twoClass {
		labels := []string{"LABEL_0", "LABEL_1"}
		if jb || inj {
			return labels, []float64{0.02, 0.98}
		}
		return labels, []float64{0.995, 0.005}
	}
	labels := []string{"BENIGN", "INJECTION", "JAILBREAK"}
	switch {
	case jb:
		return labels, []float64{0.02, 0.08, 0.90}
	case inj:
		return labels, []float64{0.03, 0.95, 0.02}
	}
	return labels, []float64{0.98, 0.015, 0.005}
}

// bagOfWords is a deterministic signed feature-hashing embedding (L2-normalized):
// texts that share words have high cosine similarity.
func bagOfWords(text string) []float64 {
	const dim = 128
	vec := make([]float64, dim)
	for _, w := range words(text) {
		h := fnv.New32a()
		h.Write([]byte(w))
		x := h.Sum32()
		sign := 1.0
		if x&(1<<31) != 0 {
			sign = -1
		}
		vec[x%dim] += sign
	}
	n := 0.0
	for _, x := range vec {
		n += x * x
	}
	if n == 0 {
		vec[0] = 1
		return vec
	}
	n = math.Sqrt(n)
	for i := range vec {
		vec[i] /= n
	}
	return vec
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
