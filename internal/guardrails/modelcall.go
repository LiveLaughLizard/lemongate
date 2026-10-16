package guardrails

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"lemongate/internal/routing"
	"lemongate/internal/settings"
)

// Shared HTTP plumbing for model-backed kinds (guard_model, semantic): resolve a
// gateway model name to a deployment and call one of its vLLM endpoints directly.

// defaultModelTimeout applies when Config.TimeoutSeconds is 0.
const defaultModelTimeout = 15 * time.Second

// upstream is a resolved deployment to call.
type upstream struct {
	dep     *routing.Deployment // nil when resolved without a registry (tests)
	apiBase string
	model   string // upstream (served) model id
	apiKey  string
	headers map[string]string
}

func (u *upstream) v1(path string) string   { return routing.V1Base(u.apiBase) + path }
func (u *upstream) root(path string) string { return routing.RootBase(u.apiBase) + path }

// resolveUpstream maps a gateway model name (or alias) to a deployment. It is a
// variable so tests can point model names at local servers without a database.
var resolveUpstream = func(e *Engine, name string) (*upstream, error) {
	if e == nil || e.registry == nil {
		return nil, errors.New("no model registry")
	}
	dep := e.registry.Pick(e.registry.Resolve(name), nil)
	if dep == nil {
		return nil, fmt.Errorf("no healthy deployment for model %q", name)
	}
	return &upstream{dep: dep, apiBase: dep.APIBase, model: dep.UpstreamModel, apiKey: dep.APIKey, headers: dep.ExtraHeaders}, nil
}

// modelTimeout is the per-check deadline for a model-backed guardrail.
func modelTimeout(c Config) time.Duration {
	if c.TimeoutSeconds > 0 {
		return time.Duration(c.TimeoutSeconds) * time.Second
	}
	return defaultModelTimeout
}

// postJSON sends body as JSON to url on the deployment and decodes the reply into out.
// Errors never include request or response content.
func (e *Engine) postJSON(ctx context.Context, u *upstream, url string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range u.headers {
		req.Header.Set(k, v)
	}
	if u.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+u.apiKey)
	}
	client := http.DefaultClient
	var rs settings.Routing
	if e != nil {
		if e.client != nil {
			client = e.client
		}
		if e.settings != nil {
			rs = e.settings.Current().Routing
		}
	}
	start := time.Now()
	if u.dep != nil {
		u.dep.Begin()
	}
	end := func(ok bool) {
		if u.dep != nil {
			u.dep.End(ok, time.Since(start), 0, rs)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		end(false)
		if ctx.Err() != nil {
			return fmt.Errorf("model %q timed out", u.model)
		}
		return fmt.Errorf("model %q request failed: %v", u.model, errors.Unwrap(err))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil || resp.StatusCode >= 300 {
		end(resp.StatusCode < 500 && err == nil)
		if err == nil {
			err = fmt.Errorf("model %q returned HTTP %d", u.model, resp.StatusCode)
		}
		return err
	}
	end(true)
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("model %q returned an unexpected response", u.model)
	}
	return nil
}

// chatMessage is one OpenAI chat message with plain-text content.
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatCompletion calls /v1/chat/completions (temperature 0, non-streaming) and
// returns the first choice's content. templateKwargs is sent as chat_template_kwargs.
func (e *Engine) chatCompletion(ctx context.Context, u *upstream, msgs []chatMessage, templateKwargs map[string]any, maxTokens int) (string, error) {
	body := map[string]any{
		"model":       u.model,
		"messages":    msgs,
		"temperature": 0,
		"max_tokens":  maxTokens,
		"stream":      false,
	}
	if len(templateKwargs) > 0 {
		body["chat_template_kwargs"] = templateKwargs
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := e.postJSON(ctx, u, u.v1("/chat/completions"), body, &out); err != nil {
		return "", err
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("model %q returned no choices", u.model)
	}
	return out.Choices[0].Message.Content, nil
}

// stripThink drops a leading reasoning block ("<think>…</think>") from model output.
func stripThink(s string) string {
	if i := strings.LastIndex(s, "</think>"); i >= 0 {
		return s[i+len("</think>"):]
	}
	return s
}
