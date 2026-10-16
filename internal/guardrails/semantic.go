package guardrails

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// semantic: flags text whose embedding is close to a known-bad example. Example
// embeddings are computed once per (model, examples) and cached; the checked text
// is split into sentences and short windows and embedded in one batch via
// POST {v1}/embeddings.

const (
	defaultSemanticThreshold = 0.85
	semanticMaxChunks        = 64
	semanticWindowChars      = 1000
	semanticMaxChars         = 32000
)

func init() {
	registerKind(KindSemantic, kindImpl{validate: validateSemantic, compile: compileSemantic, check: checkSemantic})
}

type semanticRule struct {
	threshold float64
	cacheKey  string
}

func validateSemantic(c *Config) error {
	c.Model = strings.TrimSpace(c.Model)
	if c.Model == "" {
		return errors.New("choose the embedding model")
	}
	c.Examples = cleanList(c.Examples)
	if len(c.Examples) == 0 {
		return errors.New("add at least one example text")
	}
	if c.Threshold < 0 || c.Threshold > 1 {
		return errors.New("similarity threshold must be between 0 and 1")
	}
	if c.TimeoutSeconds < 0 || c.TimeoutSeconds > 300 {
		return errors.New("timeout must be between 1 and 300 seconds")
	}
	return nil
}

func compileSemantic(r *rule) error {
	c := r.g.Config
	if len(c.Examples) == 0 {
		return errors.New("semantic guardrail has no examples")
	}
	th := c.Threshold
	if th <= 0 {
		th = defaultSemanticThreshold
	}
	h := sha256.New()
	for _, x := range c.Examples {
		h.Write([]byte(x))
		h.Write([]byte{0})
	}
	r.ext = &semanticRule{threshold: th, cacheKey: c.Model + "\x00" + hex.EncodeToString(h.Sum(nil))}
	return nil
}

// exampleCache holds normalized example embeddings keyed by model + examples hash.
var exampleCache sync.Map // string -> [][]float64

func checkSemantic(ctx context.Context, e *Engine, r *rule, in checkInput) finding {
	sr, _ := r.ext.(*semanticRule)
	if sr == nil {
		return finding{err: errors.New("semantic guardrail not compiled")}
	}
	text := joinSegments(in.segs)
	if strings.TrimSpace(text) == "" {
		return finding{}
	}
	chunks := semanticChunks(text)
	if len(chunks) == 0 {
		return finding{}
	}
	u, err := resolveUpstream(e, r.g.Config.Model)
	if err != nil {
		return finding{err: err}
	}
	ctx, cancel := context.WithTimeout(ctx, modelTimeout(r.g.Config))
	defer cancel()

	var examples [][]float64
	if v, ok := exampleCache.Load(sr.cacheKey); ok {
		examples = v.([][]float64)
	} else {
		examples, err = e.embed(ctx, u, r.g.Config.Examples)
		if err != nil {
			return finding{err: err}
		}
		exampleCache.Store(sr.cacheKey, examples)
	}
	vecs, err := e.embed(ctx, u, chunks)
	if err != nil {
		return finding{err: err}
	}
	best, bestIdx := -1.0, -1
	for _, v := range vecs {
		for j, x := range examples {
			if s := dot(v, x); s > best {
				best, bestIdx = s, j
			}
		}
	}
	detail := fmt.Sprintf("closest to example #%d (%.2f)", bestIdx+1, best)
	if bestIdx < 0 || best < sr.threshold {
		return finding{detail: detail}
	}
	return finding{hit: true, detail: fmt.Sprintf("similar to example #%d (%.2f)", bestIdx+1, best),
		reason: "resembles a known disallowed request"}
}

// embed calls /v1/embeddings and returns L2-normalized vectors in input order.
func (e *Engine) embed(ctx context.Context, u *upstream, inputs []string) ([][]float64, error) {
	var out struct {
		Data []struct {
			Index     int       `json:"index"`
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
	}
	body := map[string]any{"model": u.model, "input": inputs, "encoding_format": "float"}
	if err := e.postJSON(ctx, u, u.v1("/embeddings"), body, &out); err != nil {
		return nil, err
	}
	if len(out.Data) != len(inputs) {
		return nil, fmt.Errorf("embedding model %q returned %d vectors for %d inputs", u.model, len(out.Data), len(inputs))
	}
	vecs := make([][]float64, len(inputs))
	for i, d := range out.Data {
		idx := d.Index
		if idx < 0 || idx >= len(vecs) || vecs[idx] != nil {
			idx = i
		}
		if len(d.Embedding) == 0 {
			return nil, fmt.Errorf("embedding model %q returned an empty vector", u.model)
		}
		vecs[idx] = normalize(d.Embedding)
	}
	for _, v := range vecs {
		if v == nil {
			return nil, fmt.Errorf("embedding model %q returned an unexpected response", u.model)
		}
	}
	return vecs, nil
}

func normalize(v []float64) []float64 {
	n := 0.0
	for _, x := range v {
		n += x * x
	}
	n = math.Sqrt(n)
	out := make([]float64, len(v))
	if n == 0 {
		return out
	}
	for i, x := range v {
		out[i] = x / n
	}
	return out
}

// dot of two normalized vectors is their cosine similarity.
func dot(a, b []float64) float64 {
	n := min(len(a), len(b))
	s := 0.0
	for i := 0; i < n; i++ {
		s += a[i] * b[i]
	}
	return s
}

// semanticChunks splits text into sentences plus windows of consecutive
// sentences (up to semanticWindowChars), so both short phrases and multi-sentence
// attacks can match. The latest text wins when the chunk budget is exceeded.
func semanticChunks(text string) []string {
	if r := []rune(text); len(r) > semanticMaxChars {
		text = string(r[len(r)-semanticMaxChars:])
	}
	sents := splitSentences(text)
	seen := map[string]bool{}
	var windows, singles []string
	add := func(dst *[]string, s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		*dst = append(*dst, s)
	}
	// Windows of consecutive sentences carry multi-sentence context.
	var cur []string
	curLen := 0
	flush := func() {
		if len(cur) > 1 {
			add(&windows, strings.Join(cur, " "))
		}
	}
	for _, s := range sents {
		n := utf8.RuneCountInString(s)
		if curLen+n > semanticWindowChars && len(cur) > 0 {
			flush()
			cur, curLen = nil, 0
		}
		cur = append(cur, s)
		curLen += n + 1
	}
	flush()
	for _, s := range sents {
		if utf8.RuneCountInString(s) > semanticWindowChars {
			r := []rune(s)
			for i := 0; i < len(r); i += semanticWindowChars {
				add(&singles, string(r[i:min(i+semanticWindowChars, len(r))]))
			}
			continue
		}
		add(&singles, s)
	}
	if len(windows) > semanticMaxChunks/2 {
		windows = windows[len(windows)-semanticMaxChunks/2:]
	}
	if room := semanticMaxChunks - len(windows); len(singles) > room {
		singles = singles[len(singles)-room:]
	}
	return append(windows, singles...)
}

// splitSentences breaks text at sentence punctuation and line breaks.
func splitSentences(text string) []string {
	var out []string
	var b strings.Builder
	rs := []rune(text)
	for i, r := range rs {
		if r == '\n' || r == '\r' {
			if s := strings.TrimSpace(b.String()); s != "" {
				out = append(out, s)
			}
			b.Reset()
			continue
		}
		b.WriteRune(r)
		if r == '.' || r == '!' || r == '?' || r == '。' || r == '！' || r == '？' {
			if i+1 == len(rs) || unicode.IsSpace(rs[i+1]) || r > 127 {
				if s := strings.TrimSpace(b.String()); s != "" {
					out = append(out, s)
				}
				b.Reset()
			}
		}
	}
	if s := strings.TrimSpace(b.String()); s != "" {
		out = append(out, s)
	}
	return out
}
