// mockvllm imitates the OpenAI-compatible surface of a vLLM server for local
// development and tests. Responses are deterministic and cheap.
//
// Guard models: a served model id containing one of these substrings (case-insensitive)
// answers in that model's real output format (see guard.go):
//
//	llama-guard       chat: "safe" | "unsafe\nS1,S10" (honours chat_template_kwargs.excluded_category_keys)
//	granite-guardian  chat: "Yes" | "No" per chat_template_kwargs.guardian_config.risk_name
//	                  ("<score> yes </score>" when the id contains "3.3")
//	qwen3guard        chat: "Safety: …\nCategories: …" (+ "Refusal: …" for responses)
//	shieldgemma       /v1/completions with logprobs: first token Yes/No with top_logprobs
//	prompt-guard      POST /classify: 2-class (LABEL_0/LABEL_1) when the id contains
//	                  "prompt-guard-2", else 3-class (BENIGN/INJECTION/JAILBREAK)
//
// Triggers (case-insensitive words unless noted) in the judged text:
//
//	kill                       violent crime  (S1, violence/harm, Violent, dangerous_content)
//	bomb                       weapons        (S9, violence/harm, Violent, dangerous_content)
//	hate                       hate           (S10, social_bias/harm, Unethical Acts, hate_speech)
//	nsfw                       sexual         (S12, sexual_content, Sexual Content…, sexually_explicit)
//	UNSAFE (case-sensitive)    generic unsafe (S1, harm, Violent, every ShieldGemma principle)
//	jailbreak, "ignore [all] previous instructions"
//	                           jailbreak      (granite jailbreak, Qwen3Guard Jailbreak,
//	                                           prompt-guard high score; injection class for the latter)
//	CONTROVERSIAL (case-sensitive) Qwen3Guard "Controversial" / Politically Sensitive Topics
//
// Embeddings are a deterministic bag-of-words hashing vector (normalized), so texts
// sharing words have high cosine similarity.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"
)

var (
	addr     = flag.String("addr", ":8001", "listen address")
	models   = flag.String("models", "mock-llama", "comma-separated served model ids; ids containing llama-guard, granite-guardian, qwen3guard, shieldgemma or prompt-guard behave as guard models (triggers: kill, bomb, hate, nsfw, UNSAFE, jailbreak, \"ignore previous instructions\", CONTROVERSIAL)")
	latency  = flag.Duration("latency", 20*time.Millisecond, "artificial latency per request")
	failRate = flag.Float64("fail-rate", 0, "fraction of requests that return HTTP 500")
	maxLen   = flag.Int("max-model-len", 8192, "context window; prompts above this many tokens are rejected")
	apiKey   = flag.String("api-key", "", "require this bearer token")
)

func main() {
	flag.Parse()
	served := strings.Split(*models, ",")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "# HELP vllm:num_requests_running Mock gauge\nvllm:num_requests_running 0\n")
	})
	mux.HandleFunc("GET /v1/models", auth(func(w http.ResponseWriter, r *http.Request) {
		var data []map[string]any
		for _, m := range served {
			data = append(data, map[string]any{"id": m, "object": "model", "created": time.Now().Unix(), "owned_by": "vllm", "max_model_len": *maxLen})
		}
		writeJSON(w, 200, map[string]any{"object": "list", "data": data})
	}))
	mux.HandleFunc("POST /v1/chat/completions", auth(chat(served)))
	mux.HandleFunc("POST /v1/completions", auth(completions(served)))
	mux.HandleFunc("POST /v1/embeddings", auth(embeddings(served)))
	mux.HandleFunc("POST /v1/rerank", auth(rerank(served)))
	mux.HandleFunc("POST /v1/score", auth(rerank(served)))
	mux.HandleFunc("POST /v1/responses", auth(responses(served)))
	mux.HandleFunc("POST /v1/audio/transcriptions", auth(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseMultipartForm(32 << 20)
		writeJSON(w, 200, map[string]any{"text": "A crisp lemon a day keeps the latency away."})
	}))
	mux.HandleFunc("POST /classify", auth(classify(served)))
	mux.HandleFunc("POST /tokenize", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Prompt string `json:"prompt"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		toks := make([]int, 0)
		for i := range strings.Fields(req.Prompt) {
			toks = append(toks, 1000+i)
		}
		writeJSON(w, 200, map[string]any{"count": len(toks), "max_model_len": *maxLen, "tokens": toks})
	})
	mux.HandleFunc("POST /detokenize", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"prompt": "lemon zest"})
	})
	log.Printf("mockvllm serving %v on %s", served, *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

func auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if *apiKey != "" && r.Header.Get("Authorization") != "Bearer "+*apiKey {
			writeJSON(w, 401, map[string]any{"error": map[string]any{"message": "Unauthorized", "type": "auth_error"}})
			return
		}
		time.Sleep(*latency)
		if *failRate > 0 && rand.Float64() < *failRate {
			writeJSON(w, 500, map[string]any{"object": "error", "message": "mock internal error", "type": "InternalServerError", "code": 500})
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func countTokens(s string) int { return max(1, len(strings.Fields(s))*4/3) }

func checkModel(w http.ResponseWriter, served []string, m string) bool {
	for _, s := range served {
		if s == m {
			return true
		}
	}
	writeJSON(w, 404, map[string]any{"object": "error", "message": fmt.Sprintf("The model `%s` does not exist.", m), "type": "NotFoundError", "code": 404})
	return false
}

func contextErr(w http.ResponseWriter, n int) {
	writeJSON(w, 400, map[string]any{"object": "error", "type": "BadRequestError", "code": 400,
		"message": fmt.Sprintf("This model's maximum context length is %d tokens. However, you requested %d tokens in the messages.", *maxLen, n)})
}

var replies = []string{
	"Lemons are a hybrid of citron and bitter orange.",
	"Here is a concise answer: route traffic to the healthiest replica.",
	"Self-hosted inference keeps your data where it belongs.",
	"Paged attention lets the server batch many sequences efficiently.",
}

func chat(served []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Model    string `json:"model"`
			Stream   bool   `json:"stream"`
			Messages []struct {
				Role    string `json:"role"`
				Content any    `json:"content"`
			} `json:"messages"`
			StreamOptions *struct {
				IncludeUsage bool `json:"include_usage"`
			} `json:"stream_options"`
			MaxTokens          *int           `json:"max_tokens"`
			ChatTemplateKwargs map[string]any `json:"chat_template_kwargs"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]any{"object": "error", "message": "invalid JSON", "type": "BadRequestError", "code": 400})
			return
		}
		if !checkModel(w, served, req.Model) {
			return
		}
		var prompt strings.Builder
		for _, m := range req.Messages {
			if s, ok := m.Content.(string); ok {
				prompt.WriteString(s + " ")
			}
		}
		pt := countTokens(prompt.String())
		if pt > *maxLen || strings.Contains(prompt.String(), "OVERFLOW") {
			contextErr(w, max(pt, *maxLen+1))
			return
		}
		last := ""
		if n := len(req.Messages); n > 0 {
			last, _ = req.Messages[n-1].Content.(string)
		}
		reply := replies[len(last)%len(replies)]
		if strings.HasPrefix(strings.ToLower(last), "echo:") {
			reply = strings.TrimSpace(last[5:])
		}
		if gm := guardFamily(req.Model); gm != "" {
			var msgs []guardMsg
			for _, m := range req.Messages {
				s, _ := m.Content.(string)
				msgs = append(msgs, guardMsg{Role: m.Role, Content: s})
			}
			if out, ok := guardChat(gm, req.Model, msgs, req.ChatTemplateKwargs); ok {
				reply = out
			}
		}
		ct := countTokens(reply)
		id := fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano())
		usage := map[string]any{"prompt_tokens": pt, "completion_tokens": ct, "total_tokens": pt + ct}
		if !req.Stream {
			writeJSON(w, 200, map[string]any{"id": id, "object": "chat.completion", "created": time.Now().Unix(), "model": req.Model,
				"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": reply}, "finish_reason": "stop"}},
				"usage":   usage})
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		send := func(v any) {
			b, _ := json.Marshal(v)
			fmt.Fprintf(w, "data: %s\n\n", b)
			fl.Flush()
		}
		base := func(delta map[string]any, finish any) map[string]any {
			return map[string]any{"id": id, "object": "chat.completion.chunk", "created": time.Now().Unix(), "model": req.Model,
				"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}}}
		}
		send(base(map[string]any{"role": "assistant", "content": ""}, nil))
		for _, word := range strings.SplitAfter(reply, " ") {
			time.Sleep(15 * time.Millisecond)
			send(base(map[string]any{"content": word}, nil))
		}
		send(base(map[string]any{}, "stop"))
		if req.StreamOptions != nil && req.StreamOptions.IncludeUsage {
			send(map[string]any{"id": id, "object": "chat.completion.chunk", "created": time.Now().Unix(), "model": req.Model, "choices": []any{}, "usage": usage})
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
		fl.Flush()
	}
}

func completions(served []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Model    string `json:"model"`
			Prompt   string `json:"prompt"`
			Stream   bool   `json:"stream"`
			Logprobs *int   `json:"logprobs"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if !checkModel(w, served, req.Model) {
			return
		}
		pt := countTokens(req.Prompt)
		if pt > *maxLen {
			contextErr(w, pt)
			return
		}
		text := " and that is why citrus matters."
		var logprobs any
		if guardFamily(req.Model) == "shieldgemma" {
			text, logprobs = shieldGemmaCompletion(req.Prompt, req.Logprobs)
		}
		ct := countTokens(text)
		writeJSON(w, 200, map[string]any{"id": "cmpl-mock", "object": "text_completion", "created": time.Now().Unix(), "model": req.Model,
			"choices": []any{map[string]any{"index": 0, "text": text, "logprobs": logprobs, "finish_reason": "stop"}},
			"usage":   map[string]any{"prompt_tokens": pt, "completion_tokens": ct, "total_tokens": pt + ct}})
	}
}

func embeddings(served []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Model string `json:"model"`
			Input any    `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
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
		var data []any
		pt := 0
		for i, in := range inputs {
			pt += countTokens(in)
			data = append(data, map[string]any{"object": "embedding", "index": i, "embedding": bagOfWords(in)})
		}
		writeJSON(w, 200, map[string]any{"object": "list", "model": req.Model, "data": data,
			"usage": map[string]any{"prompt_tokens": pt, "total_tokens": pt}})
	}
}

func rerank(served []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Model     string   `json:"model"`
			Query     string   `json:"query"`
			Documents []string `json:"documents"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if !checkModel(w, served, req.Model) {
			return
		}
		var results []any
		total := countTokens(req.Query)
		for i, d := range req.Documents {
			total += countTokens(d)
			results = append(results, map[string]any{"index": i, "relevance_score": 1 / float64(i+1), "document": map[string]any{"text": d}})
		}
		writeJSON(w, 200, map[string]any{"id": "rerank-mock", "model": req.Model, "results": results, "usage": map[string]any{"total_tokens": total}})
	}
}

func responses(served []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Model string `json:"model"`
			Input any    `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if !checkModel(w, served, req.Model) {
			return
		}
		text := replies[0]
		writeJSON(w, 200, map[string]any{"id": "resp_mock", "object": "response", "model": req.Model, "status": "completed",
			"output": []any{map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": text}}}},
			"usage":  map[string]any{"input_tokens": 12, "output_tokens": countTokens(text), "total_tokens": 12 + countTokens(text)}})
	}
}
