package guardrails

import "strings"

// segment is one piece of user-visible text inside a request or response body,
// with a setter that writes a (masked) replacement back into the body.
type segment struct {
	text string
	set  func(string)
}

// requestSegments collects the text an LLM will read from an OpenAI-style request:
// chat messages (string or array-of-parts content), completion prompts and
// embedding / responses-API inputs.
func requestSegments(body map[string]any) []*segment {
	var out []*segment
	if msgs, ok := body["messages"].([]any); ok {
		for _, m := range msgs {
			if mm, ok := m.(map[string]any); ok {
				out = appendContent(out, mm, "content")
			}
		}
	}
	for _, k := range []string{"prompt", "input", "instructions"} {
		out = appendAny(out, body, k)
	}
	// Rerank / score requests.
	for _, k := range []string{"query", "documents", "text_1", "text_2"} {
		out = appendAny(out, body, k)
	}
	return out
}

// responseSegments collects generated text from an OpenAI-style response.
func responseSegments(body map[string]any) []*segment {
	var out []*segment
	if choices, ok := body["choices"].([]any); ok {
		for _, c := range choices {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			if msg, ok := cm["message"].(map[string]any); ok {
				out = appendContent(out, msg, "content")
				out = appendString(out, msg, "reasoning_content")
			}
			out = appendString(out, cm, "text")
		}
	}
	// Responses API: output[].content[].text
	if items, ok := body["output"].([]any); ok {
		for _, it := range items {
			if im, ok := it.(map[string]any); ok {
				out = appendContent(out, im, "content")
			}
		}
	}
	return out
}

func appendString(out []*segment, m map[string]any, k string) []*segment {
	if s, ok := m[k].(string); ok && s != "" {
		out = append(out, &segment{text: s, set: func(v string) { m[k] = v }})
	}
	return out
}

// appendContent handles a message-like "content" field: a string, or an array of
// parts where text parts carry "text".
func appendContent(out []*segment, m map[string]any, k string) []*segment {
	switch v := m[k].(type) {
	case string:
		return appendString(out, m, k)
	case []any:
		for i, p := range v {
			switch pv := p.(type) {
			case map[string]any:
				out = appendString(out, pv, "text")
			case string:
				out = appendIndex(out, v, i)
			}
		}
	}
	return out
}

// appendAny handles prompt/input style fields: string, []string, or arrays of
// message items (responses API) or text parts.
func appendAny(out []*segment, m map[string]any, k string) []*segment {
	switch v := m[k].(type) {
	case string:
		return appendString(out, m, k)
	case []any:
		for i, it := range v {
			switch iv := it.(type) {
			case map[string]any:
				if _, has := iv["content"]; has {
					out = appendContent(out, iv, "content")
				} else {
					out = appendString(out, iv, "text")
				}
			case string:
				out = appendIndex(out, v, i)
			}
		}
	}
	return out
}

func appendIndex(out []*segment, arr []any, i int) []*segment {
	if s, ok := arr[i].(string); ok && s != "" {
		out = append(out, &segment{text: s, set: func(v string) { arr[i] = v }})
	}
	return out
}

func joinSegments(segs []*segment) string {
	parts := make([]string, 0, len(segs))
	for _, s := range segs {
		parts = append(parts, s.text)
	}
	return strings.Join(parts, "\n")
}

// redactValue masks PII in every string of a decoded JSON value, in place where possible.
func redactValue(v any) any {
	switch t := v.(type) {
	case string:
		out, _ := MaskPII(t, nil)
		return out
	case map[string]any:
		for k, x := range t {
			t[k] = redactValue(x)
		}
		return t
	case []any:
		for i, x := range t {
			t[i] = redactValue(x)
		}
		return t
	}
	return v
}
