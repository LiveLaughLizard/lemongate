package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	"lemongate/internal/auth"
	"lemongate/internal/hooks"
	"lemongate/internal/metrics"
	"lemongate/internal/routing"
	"lemongate/internal/spend"
)

// handleTranscription forwards multipart audio requests, swapping in the upstream model id.
func (g *Gateway) handleTranscription(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	p := auth.FromContext(r.Context())
	route := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/v1"), "/")
	reqID := newRequestID()
	w.Header().Set("x-lemongate-request-id", reqID)
	c := &call{ep: endpoint{route: route}, p: p, start: start,
		info: hooks.CallInfo{RequestID: reqID, Route: route, Principal: p},
		rec: spend.Record{RequestID: reqID, Route: route, KeyID: p.KeyID(), UserID: p.UserID(), TeamID: p.TeamID(),
			OrgID: p.OrgID(), Metadata: map[string]any{}}}
	if p.Key != nil {
		c.rec.KeyAlias = p.Key.Alias
		c.rec.Tags = p.Key.Tags
	}
	// Budgets and rate limits apply before the upload is read.
	if err := g.checkBudgets(r.Context(), p, "", c.rec.Tags); err != nil {
		metrics.BudgetRejected.Inc()
		g.fail(w, c, &APIError{Status: 429, Message: err.Error(), Type: "budget_exceeded", Code: "budget_exceeded"}, "blocked")
		return
	}
	release, _, err := g.Limiter.Acquire(limitSubjects(p))
	if err != nil {
		g.fail(w, c, &APIError{Status: 429, Message: err.Error(), Type: "rate_limit_exceeded"}, "blocked")
		return
	}
	defer release(0)

	r.Body = http.MaxBytesReader(w, r.Body, maxBody(g.Settings.Current()))
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		if errors.As(err, new(*http.MaxBytesError)) {
			WriteError(w, errBody(err))
		} else {
			WriteError(w, errBadRequest("expected multipart/form-data body: "+err.Error()))
		}
		return
	}
	requested := r.FormValue("model")
	group := g.Registry.Resolve(requested)
	if !g.Registry.HasGroup(group) {
		WriteError(w, errNotFound(fmt.Sprintf("The model '%s' does not exist or you do not have access to it.", requested)))
		return
	}
	if !p.CanUseModel(g.Registry, group) {
		WriteError(w, errForbidden(fmt.Sprintf("This key is not allowed to access model '%s'.", requested)))
		return
	}
	c.requested, c.group, c.info.Model = requested, group, group
	c.rec.Model, c.rec.ModelGroup = requested, group

	rs := g.Settings.Current().Routing
	exclude := map[string]bool{}
	var lastErr *APIError
	for attempt := 0; attempt <= rs.NumRetries; attempt++ {
		dep := g.Registry.Pick(group, exclude)
		if dep == nil {
			break
		}
		c.rec.Attempts++
		sent := time.Now()
		resp, err := g.sendMultipart(r.Context(), dep, r.MultipartForm, route)
		if err != nil || resp.StatusCode >= 500 || resp.StatusCode == 429 {
			// A client that hangs up must not count against the deployment.
			dep.End(err != nil && r.Context().Err() != nil, time.Since(sent), 0, rs)
			exclude[dep.ID] = true
			if err != nil {
				// The transport error names the upstream URL: keep it out of the client message.
				lastErr = &APIError{Status: 502, Type: "upstream_error", Code: "upstream_unreachable",
					Message: fmt.Sprintf("upstream request for model '%s' failed", group),
					detail:  fmt.Sprintf("upstream %s for model '%s' failed: %v", routing.RedactBase(dep.APIBase), group, err)}
				if r.Context().Err() == nil {
					slog.Warn("upstream request failed", "request_id", reqID, "model", group, "api_base", routing.RedactBase(dep.APIBase), "err", err)
				}
			} else {
				b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
				resp.Body.Close()
				lastErr = upstreamError(resp.StatusCode, b)
			}
			continue
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		lat := time.Since(start)
		dep.End(resp.StatusCode < 400, lat, 0, rs)
		c.rec.DeploymentID, c.rec.APIBase = depID(dep), routing.RedactBase(dep.APIBase)
		c.rec.HTTPStatus, c.rec.LatencyMs, c.rec.Status = resp.StatusCode, int(lat.Milliseconds()), "success"
		if resp.StatusCode >= 400 {
			c.rec.Status = "error"
			c.rec.Error = upstreamError(resp.StatusCode, body).Message
		}
		g.record(c.rec)
		copyHeaders(w, resp)
		w.Header().Set("x-lemongate-model", group)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
		return
	}
	if lastErr == nil {
		lastErr = &APIError{Status: 503, Type: "upstream_error", Message: "no available deployments for model '" + group + "'"}
	}
	g.fail(w, c, lastErr, "error")
}

func (g *Gateway) sendMultipart(ctx context.Context, dep *routing.Deployment, form *multipart.Form, route string) (*http.Response, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, vs := range form.Value {
		for _, v := range vs {
			if k == "model" {
				v = dep.UpstreamModel
			}
			_ = mw.WriteField(k, v)
		}
	}
	for k, fhs := range form.File {
		for _, fh := range fhs {
			f, err := fh.Open()
			if err != nil {
				return nil, err
			}
			part, err := mw.CreateFormFile(k, fh.Filename)
			if err == nil {
				_, err = io.Copy(part, f)
			}
			f.Close()
			if err != nil {
				return nil, err
			}
		}
	}
	_ = mw.Close()
	timeout := time.Duration(max(dep.TimeoutSeconds, 30)) * time.Second
	rctx, cancel := context.WithTimeout(ctx, timeout)
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, routing.V1Base(dep.APIBase)+"/"+route, &buf)
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
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
