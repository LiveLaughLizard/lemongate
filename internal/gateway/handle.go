package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"lemongate/internal/auth"
	"lemongate/internal/hooks"
	"lemongate/internal/limits"
	"lemongate/internal/metrics"
	"lemongate/internal/routing"
	"lemongate/internal/spend"
	"lemongate/internal/store"
)

type endpoint struct {
	route  string // path relative to the upstream base, e.g. "chat/completions"
	mode   string // informational
	stream bool   // supports SSE streaming
	root   bool   // upstream path is server-root (not under /v1)
	free   bool   // not billed or logged (utility endpoints)
}

// Fields understood by the gateway and stripped before forwarding upstream.
var gatewayFields = []string{"guardrails", "metadata", "tags", "cache"}

// call carries per-request state through the pipeline.
type call struct {
	ep            endpoint
	p             *auth.Principal
	info          hooks.CallInfo
	rec           spend.Record
	start         time.Time
	payload       map[string]any
	requested     string // model name as sent by the client
	group         string
	injectedUsage bool
}

func (g *Gateway) handle(ep endpoint) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st := g.Settings.Current()
		p := auth.FromContext(r.Context())
		c := &call{ep: ep, p: p, start: time.Now()}
		reqID := newRequestID()
		w.Header().Set("x-lemongate-request-id", reqID)

		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(max(st.General.MaxRequestBytes, 1<<20))))
		if err != nil {
			WriteError(w, errBadRequest("request body too large or unreadable"))
			return
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&c.payload); err != nil || c.payload == nil {
			WriteError(w, errBadRequest("request body must be a JSON object"))
			return
		}
		c.requested, _ = c.payload["model"].(string)
		if c.requested == "" {
			WriteError(w, &APIError{Status: 400, Message: "you must provide a model parameter", Type: "invalid_request_error", Param: "model"})
			return
		}
		c.group = g.Registry.Resolve(c.requested)
		if !g.Registry.HasGroup(c.group) {
			WriteError(w, errNotFound(fmt.Sprintf("The model '%s' does not exist or you do not have access to it.", c.requested)))
			return
		}
		if !p.CanUseModel(g.Registry, c.group) {
			WriteError(w, errForbidden(fmt.Sprintf("This key is not allowed to access model '%s'.", c.requested)))
			return
		}

		stream := ep.stream && c.payload["stream"] == true
		tags := requestTags(r, c.payload, p)
		endUser := ""
		if u, ok := c.payload["user"].(string); ok && st.General.TrackEndUsers {
			endUser = u
		}
		c.info = hooks.CallInfo{RequestID: reqID, Route: ep.route, Model: c.group, Principal: p, Stream: stream,
			RequestedGuardrails: stringList(c.payload["guardrails"])}
		c.rec = spend.Record{RequestID: reqID, Route: ep.route, Model: c.requested, ModelGroup: c.group,
			KeyID: p.KeyID(), UserID: p.UserID(), TeamID: p.TeamID(), OrgID: p.OrgID(), EndUser: endUser,
			Tags: tags, Stream: stream, Metadata: map[string]any{}}
		if p.Key != nil {
			c.rec.KeyAlias = p.Key.Alias
		}
		if md, ok := c.payload["metadata"].(map[string]any); ok {
			c.rec.Metadata = md
		}
		for _, f := range gatewayFields {
			delete(c.payload, f)
		}
		c.info.Request = c.payload

		if !ep.free {
			if err := g.checkBudgets(r.Context(), p, endUser, tags); err != nil {
				metrics.BudgetRejected.Inc()
				g.fail(w, c, &APIError{Status: 429, Message: err.Error(), Type: "budget_exceeded", Code: "budget_exceeded"}, "blocked")
				return
			}
		}
		release, rem, err := g.Limiter.Acquire(limitSubjects(p))
		if err != nil {
			var le *limits.LimitError
			if errors.As(err, &le) {
				w.Header().Set("Retry-After", strconv.Itoa(int(le.Retry.Seconds())))
				metrics.RateLimited.WithLabelValues(le.Kind).Inc()
			}
			g.fail(w, c, &APIError{Status: 429, Message: err.Error(), Type: "rate_limit_exceeded", Code: "rate_limit_exceeded"}, "blocked")
			return
		}
		tokensUsed := 0
		defer func() { release(tokensUsed) }()
		if rem.Requests >= 0 {
			w.Header().Set("x-ratelimit-remaining-requests", strconv.Itoa(rem.Requests))
		}
		if rem.Tokens >= 0 {
			w.Header().Set("x-ratelimit-remaining-tokens", strconv.Itoa(rem.Tokens))
		}

		if g.Guardrails != nil && !ep.free {
			if err := g.Guardrails.PreCall(r.Context(), c.info, c.payload); err != nil {
				g.guardrailFail(w, c, err)
				return
			}
		}
		if st.Logging.StorePayloads && !ep.free {
			c.rec.RequestBody = g.capturePayload(c.payload)
		}

		if stream && (ep.route == "chat/completions" || ep.route == "completions") {
			so, _ := c.payload["stream_options"].(map[string]any)
			if so == nil {
				so = map[string]any{}
			}
			if so["include_usage"] != true {
				so["include_usage"] = true
				c.injectedUsage = true
			}
			c.payload["stream_options"] = so
		}

		var cacheKey string
		cacheable := g.Cache != nil && st.Cache.Enabled && !stream && !ep.free
		cc := strings.ToLower(r.Header.Get("Cache-Control"))
		if cacheable {
			var ok bool
			cacheKey, ok = g.Cache.Key(c.info, c.payload)
			cacheable = ok
		}
		if cacheable && !strings.Contains(cc, "no-cache") {
			if body, ok := g.Cache.Get(cacheKey); ok {
				metrics.CacheLookups.WithLabelValues("hit").Inc()
				g.serveCached(w, c, body)
				return
			}
			metrics.CacheLookups.WithLabelValues("miss").Inc()
		}

		resp, dep, apiErr := g.dispatch(r.Context(), c)
		if apiErr != nil {
			g.fail(w, c, apiErr, "error")
			return
		}
		defer resp.Body.Close()
		c.rec.DeploymentID = depID(dep)
		c.rec.APIBase = dep.APIBase
		w.Header().Set("x-lemongate-model", c.group)
		w.Header().Set("x-lemongate-deployment", dep.ID)
		if cacheable {
			w.Header().Set("x-lemongate-cache", "miss")
		}

		if stream && strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
			tokensUsed = g.relayStream(r.Context(), w, resp, c, dep)
			return
		}
		ttl := time.Duration(st.Cache.TTLSeconds) * time.Second
		if v, err := strconv.Atoi(r.Header.Get("x-lemongate-cache-ttl")); err == nil && v > 0 {
			ttl = time.Duration(v) * time.Second
		}
		storeCache := cacheable && !strings.Contains(cc, "no-store")
		tokensUsed = g.relayJSON(r.Context(), w, resp, c, dep, storeCache, cacheKey, ttl)
	}
}

func depID(d *routing.Deployment) string {
	if d.FromConfig {
		return ""
	}
	return d.ID
}

// dispatch sends the request with retries across deployments and fallback groups.
// On success the caller owns resp.Body; dep.End has NOT yet been called.
func (g *Gateway) dispatch(ctx context.Context, c *call) (*http.Response, *routing.Deployment, *APIError) {
	rs := g.Settings.Current().Routing
	groups := append([]string{c.group}, g.Registry.Fallbacks(c.group, false)...)
	var lastErr *APIError
	tried := map[string]bool{}
	for gi := 0; gi < len(groups); gi++ {
		group := g.Registry.Resolve(groups[gi])
		if tried[group] {
			continue
		}
		tried[group] = true
		if gi > 0 && !c.p.CanUseModel(g.Registry, group) {
			continue
		}
		exclude := map[string]bool{}
		for attempt := 0; attempt <= max(rs.NumRetries, 0); attempt++ {
			dep := g.Registry.Pick(group, exclude)
			if dep == nil {
				break
			}
			if attempt > 0 || gi > 0 {
				backoff := time.Duration(rs.RetryBackoffMs) * time.Millisecond * time.Duration(1<<min(attempt, 4))
				select {
				case <-ctx.Done():
					return nil, nil, &APIError{Status: 499, Message: "client closed request", Type: "api_error"}
				case <-time.After(backoff):
				}
			}
			c.rec.Attempts++
			if gi > 0 {
				c.rec.Metadata["fallback_from"] = c.group
				c.rec.ModelGroup = group
				if attempt == 0 {
					from, kind := c.group, "general"
					if cf, ok := c.rec.Metadata["context_fallback_from"].(string); ok {
						from, kind = cf, "context_window"
					}
					metrics.Fallbacks.WithLabelValues(from, group, kind).Inc()
				}
			}
			if attempt > 0 {
				metrics.Retries.WithLabelValues(group).Inc()
			}
			lv := []string{dep.Name, dep.APIBase, dep.ID}
			sent := time.Now()
			resp, err := g.send(ctx, dep, c, group)
			if err != nil {
				dep.End(false, 0, 0, rs)
				if ctx.Err() == nil {
					metrics.UpstreamRequests.WithLabelValues(append(lv, "error")...).Inc()
					metrics.DeploymentFailures.WithLabelValues(lv...).Inc()
				}
				exclude[dep.ID] = true
				lastErr = &APIError{Status: http.StatusBadGateway, Type: "upstream_error", Code: "upstream_unreachable",
					Message: fmt.Sprintf("upstream %s for model '%s' failed: %v", dep.APIBase, group, err)}
				if ctx.Err() != nil {
					return nil, nil, lastErr
				}
				continue
			}
			metrics.UpstreamRequests.WithLabelValues(append(lv, metrics.CodeClass(resp.StatusCode))...).Inc()
			metrics.UpstreamLatency.WithLabelValues(lv...).Observe(time.Since(sent).Seconds())
			if resp.StatusCode < 400 {
				return resp, dep, nil
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			upstreamErr := upstreamError(resp.StatusCode, body)
			switch {
			case resp.StatusCode == 429 || resp.StatusCode >= 500:
				dep.End(false, 0, 0, rs)
				metrics.DeploymentFailures.WithLabelValues(lv...).Inc()
				exclude[dep.ID] = true
				lastErr = upstreamErr
				continue
			case isContextLengthError(resp.StatusCode, body):
				dep.End(true, 0, 0, rs)
				if cf := g.Registry.Fallbacks(group, true); len(cf) > 0 {
					c.rec.Metadata["context_fallback_from"] = group
					groups = append(groups[:gi+1], cf...)
					lastErr = upstreamErr
					attempt = rs.NumRetries + 1 // move to the next group
					continue
				}
				return nil, nil, upstreamErr
			default:
				// Client error: retrying elsewhere will not help.
				dep.End(true, 0, 0, rs)
				return nil, nil, upstreamErr
			}
		}
	}
	if lastErr == nil {
		lastErr = &APIError{Status: http.StatusServiceUnavailable, Type: "upstream_error", Code: "no_deployments",
			Message: fmt.Sprintf("no available deployments for model '%s'", c.group)}
	}
	return nil, nil, lastErr
}

func (g *Gateway) send(ctx context.Context, dep *routing.Deployment, c *call, group string) (*http.Response, error) {
	payload := make(map[string]any, len(c.payload))
	for k, v := range c.payload {
		payload[k] = v
	}
	payload["model"] = dep.UpstreamModel
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	base := routing.V1Base(dep.APIBase)
	if c.ep.root {
		base = routing.RootBase(dep.APIBase)
	}
	timeout := time.Duration(dep.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = time.Duration(g.Settings.Current().Routing.DefaultTimeoutSec) * time.Second
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, base+"/"+c.ep.route, bytes.NewReader(body))
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", c.info.RequestID)
	if dep.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+dep.APIKey)
	}
	for k, v := range dep.ExtraHeaders {
		req.Header.Set(k, v)
	}
	dep.Begin()
	resp, err := g.client.Do(req)
	if err != nil {
		cancel()
		return nil, err
	}
	resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelOnClose) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}

func upstreamError(status int, body []byte) *APIError {
	var e struct {
		Error   json.RawMessage `json:"error"`
		Message string          `json:"message"`
		Object  string          `json:"object"`
	}
	msg := strings.TrimSpace(string(body))
	if json.Unmarshal(body, &e) == nil {
		var inner struct {
			Message string `json:"message"`
		}
		if len(e.Error) > 0 && json.Unmarshal(e.Error, &inner) == nil && inner.Message != "" {
			msg = inner.Message
		} else if e.Message != "" {
			msg = e.Message
		}
	}
	if len(msg) > 2000 {
		msg = msg[:2000]
	}
	if msg == "" {
		msg = http.StatusText(status)
	}
	typ := "upstream_error"
	if status < 500 {
		typ = "invalid_request_error"
	}
	return &APIError{Status: status, Message: msg, Type: typ}
}

func isContextLengthError(status int, body []byte) bool {
	if status != 400 {
		return false
	}
	s := strings.ToLower(string(body))
	return strings.Contains(s, "maximum context length") || strings.Contains(s, "context length") ||
		strings.Contains(s, "too many tokens") || strings.Contains(s, "max_model_len")
}

// usage is normalized token accounting from any OpenAI-style response.
type usage struct{ prompt, completion int }

func parseUsage(m map[string]any) (usage, bool) {
	u, ok := m["usage"].(map[string]any)
	if !ok {
		return usage{}, false
	}
	n := func(k string) int {
		switch v := u[k].(type) {
		case json.Number:
			i, _ := v.Int64()
			return int(i)
		case float64:
			return int(v)
		}
		return 0
	}
	out := usage{prompt: n("prompt_tokens"), completion: n("completion_tokens")}
	if out.prompt == 0 && out.completion == 0 {
		out.prompt, out.completion = n("input_tokens"), n("output_tokens")
	}
	if out.prompt == 0 && out.completion == 0 {
		out.prompt = n("total_tokens")
	}
	return out, true
}

func (g *Gateway) relayJSON(ctx context.Context, w http.ResponseWriter, resp *http.Response, c *call, dep *routing.Deployment, storeCache bool, cacheKey string, ttl time.Duration) int {
	rs := g.Settings.Current().Routing
	body, err := io.ReadAll(resp.Body)
	latency := time.Since(c.start)
	if err != nil {
		dep.End(false, latency, 0, rs)
		g.fail(w, c, &APIError{Status: 502, Type: "upstream_error", Message: "error reading upstream response: " + err.Error()}, "error")
		return 0
	}
	c.rec.LatencyMs = int(latency.Milliseconds())
	c.rec.HTTPStatus = resp.StatusCode
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if dec.Decode(&m) != nil || m == nil {
		// Not JSON: relay verbatim.
		dep.End(true, latency, 0, rs)
		c.rec.Status = "success"
		if !c.ep.free {
			g.record(c.rec)
		}
		copyHeaders(w, resp)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
		return 0
	}
	u, _ := parseUsage(m)
	dep.End(true, latency, u.prompt+u.completion, rs)
	if _, ok := m["model"]; ok {
		m["model"] = c.requested
	}
	if g.Guardrails != nil && !c.ep.free {
		if err := g.Guardrails.PostCall(ctx, c.info, m); err != nil {
			c.rec.PromptTokens, c.rec.CompletionTokens = u.prompt, u.completion
			c.rec.Cost = spend.Cost(u.prompt, u.completion, dep.InputCostPerM, dep.OutputCostPerM)
			g.guardrailFail(w, c, err)
			return u.prompt + u.completion
		}
	}
	out, _ := json.Marshal(m)
	c.rec.PromptTokens, c.rec.CompletionTokens = u.prompt, u.completion
	c.rec.Cost = spend.Cost(u.prompt, u.completion, dep.InputCostPerM, dep.OutputCostPerM)
	c.rec.Status = "success"
	if g.Settings.Current().Logging.StorePayloads && !c.ep.free {
		c.rec.ResponseBody = g.capturePayload(m)
	}
	if storeCache {
		g.Cache.Set(cacheKey, out, ttl)
	}
	w.Header().Set("x-lemongate-cost", strconv.FormatFloat(c.rec.Cost, 'f', 8, 64))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(out)
	if !c.ep.free {
		g.record(c.rec)
	}
	return u.prompt + u.completion
}

func copyHeaders(w http.ResponseWriter, resp *http.Response) {
	for _, h := range []string{"Content-Type", "Cache-Control"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
}

// relayStream proxies an SSE stream, rewriting the model name, capturing usage
// and time-to-first-token. Returns total tokens.
func (g *Gateway) relayStream(ctx context.Context, w http.ResponseWriter, resp *http.Response, c *call, dep *routing.Deployment) int {
	rs := g.Settings.Current().Routing
	flusher, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(resp.StatusCode)
	if flusher != nil {
		flusher.Flush()
	}
	upstreamName, _ := json.Marshal(dep.UpstreamModel)
	clientName, _ := json.Marshal(c.requested)
	fromModel := append([]byte(`"model":`), upstreamName...)
	toModel := append([]byte(`"model":`), clientName...)

	var u usage
	var text strings.Builder
	var ttft *int
	reader := bufio.NewReaderSize(resp.Body, 64<<10)
	var readErr error
	clientGone := false
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			skip := false
			if bytes.HasPrefix(line, []byte("data:")) {
				data := bytes.TrimSpace(line[5:])
				if !bytes.Equal(data, []byte("[DONE]")) && len(data) > 0 && data[0] == '{' {
					var chunk map[string]any
					if json.Unmarshal(data, &chunk) == nil {
						if cu, ok := parseUsage(chunk); ok {
							u = cu
						}
						choices, _ := chunk["choices"].([]any)
						if piece := chunkText(chunk, choices); piece != "" {
							if ttft == nil {
								v := int(time.Since(c.start).Milliseconds())
								ttft = &v
							}
							if text.Len() < 1<<20 {
								text.WriteString(piece)
							}
						}
						// Drop the usage-only trailer if the client did not ask for it.
						if c.injectedUsage && len(choices) == 0 && chunk["usage"] != nil {
							skip = true
						}
					}
					line = bytes.Replace(line, fromModel, toModel, 1)
				}
			}
			if !skip {
				if _, werr := w.Write(line); werr != nil {
					clientGone = true
					break
				}
				if flusher != nil && (len(bytes.TrimSpace(line)) == 0) {
					flusher.Flush()
				}
			} else {
				// swallow the trailing blank line of the skipped event
				if next, _ := reader.Peek(1); len(next) == 1 && next[0] == '\n' {
					_, _ = reader.ReadByte()
				}
			}
		}
		if err != nil {
			if err != io.EOF {
				readErr = err
			}
			break
		}
	}
	if flusher != nil {
		flusher.Flush()
	}
	latency := time.Since(c.start)
	dep.End(readErr == nil, latency, u.prompt+u.completion, rs)
	c.rec.LatencyMs = int(latency.Milliseconds())
	c.rec.TTFTMs = ttft
	c.rec.HTTPStatus = resp.StatusCode
	c.rec.PromptTokens, c.rec.CompletionTokens = u.prompt, u.completion
	c.rec.Cost = spend.Cost(u.prompt, u.completion, dep.InputCostPerM, dep.OutputCostPerM)
	c.rec.Status = "success"
	if readErr != nil {
		c.rec.Status = "error"
		c.rec.Error = "upstream stream interrupted: " + readErr.Error()
	} else if clientGone {
		c.rec.Metadata["client_disconnected"] = true
	}
	if g.Settings.Current().Logging.StorePayloads {
		c.rec.ResponseBody = g.capturePayload(map[string]any{"stream_text": text.String()})
	}
	if g.Guardrails != nil {
		g.Guardrails.PostStream(context.WithoutCancel(ctx), c.info, text.String())
	}
	g.record(c.rec)
	return u.prompt + u.completion
}

func chunkText(chunk map[string]any, choices []any) string {
	var sb strings.Builder
	for _, ch := range choices {
		cm, _ := ch.(map[string]any)
		if cm == nil {
			continue
		}
		if d, ok := cm["delta"].(map[string]any); ok {
			if s, ok := d["content"].(string); ok {
				sb.WriteString(s)
			}
			if s, ok := d["reasoning_content"].(string); ok && sb.Len() == 0 {
				sb.WriteString(s)
			}
		}
		if s, ok := cm["text"].(string); ok {
			sb.WriteString(s)
		}
	}
	if t, _ := chunk["type"].(string); t == "response.output_text.delta" {
		if s, ok := chunk["delta"].(string); ok {
			sb.WriteString(s)
		}
	}
	return sb.String()
}

func (g *Gateway) serveCached(w http.ResponseWriter, c *call, body []byte) {
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	u, _ := parseUsage(m)
	c.rec.CacheHit = true
	c.rec.Status = "success"
	c.rec.HTTPStatus = 200
	c.rec.PromptTokens, c.rec.CompletionTokens = u.prompt, u.completion
	c.rec.LatencyMs = int(time.Since(c.start).Milliseconds())
	c.rec.Metadata["cache"] = "hit"
	if g.Settings.Current().Logging.StorePayloads {
		c.rec.ResponseBody = g.capturePayload(m)
	}
	w.Header().Set("x-lemongate-cache", "hit")
	w.Header().Set("x-lemongate-model", c.group)
	w.Header().Set("x-lemongate-cost", "0")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(body)
	g.record(c.rec)
}

func (g *Gateway) fail(w http.ResponseWriter, c *call, e *APIError, status string) {
	c.rec.Status = status
	c.rec.HTTPStatus = e.Status
	c.rec.Error = e.Message
	c.rec.LatencyMs = int(time.Since(c.start).Milliseconds())
	if !c.ep.free {
		g.record(c.rec)
	}
	WriteError(w, e)
}

func (g *Gateway) guardrailFail(w http.ResponseWriter, c *call, err error) {
	var gb *hooks.GuardrailBlock
	if errors.As(err, &gb) {
		c.rec.Metadata["guardrail"] = gb.Guardrail
		g.fail(w, c, &APIError{Status: 400, Message: gb.Error(), Type: "guardrail_violation", Code: "content_blocked"}, "blocked")
		return
	}
	g.fail(w, c, &APIError{Status: 500, Message: "guardrail error: " + err.Error(), Type: "api_error"}, "error")
}

func (g *Gateway) capturePayload(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	lg := g.Settings.Current().Logging
	if lg.MaxPayloadBytes > 0 && len(b) > lg.MaxPayloadBytes {
		b, _ = json.Marshal(map[string]any{"truncated": true, "bytes": len(b), "preview": string(b[:min(len(b), 2048)])})
	}
	if lg.RedactPayloads && g.Redact != nil {
		b = g.Redact(b)
	}
	return b
}

func requestTags(r *http.Request, payload map[string]any, p *auth.Principal) []string {
	var tags []string
	if h := r.Header.Get("x-lemongate-tags"); h != "" {
		tags = append(tags, strings.Split(h, ",")...)
	}
	tags = append(tags, stringList(payload["tags"])...)
	if md, ok := payload["metadata"].(map[string]any); ok {
		tags = append(tags, stringList(md["tags"])...)
	}
	if p.Key != nil {
		tags = append(tags, p.Key.Tags...)
	}
	out := store.CleanList(tags)
	slices.Sort(out)
	return out
}

func stringList(v any) []string {
	switch t := v.(type) {
	case []any:
		var out []string
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	case string:
		return strings.Split(t, ",")
	}
	return nil
}
