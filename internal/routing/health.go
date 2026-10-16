package routing

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"lemongate/internal/hooks"
)

// V1Base normalizes an API base so it ends in /v1 (vLLM's OpenAI-compatible root).
func V1Base(apiBase string) string {
	b := strings.TrimRight(apiBase, "/")
	if !strings.HasSuffix(b, "/v1") {
		b += "/v1"
	}
	return b
}

// RootBase strips the /v1 suffix, for server-level endpoints like /health and /tokenize.
func RootBase(apiBase string) string {
	return strings.TrimSuffix(strings.TrimRight(apiBase, "/"), "/v1")
}

// Prober periodically checks every deployment's health.
type Prober struct {
	reg     *Registry
	client  *http.Client
	alerter hooks.Alerter
	OnCheck func(d *Deployment, h Health) // optional persistence/metrics callback
}

func NewProber(reg *Registry, alerter hooks.Alerter) *Prober {
	if alerter == nil {
		alerter = hooks.NopAlerter
	}
	return &Prober{reg: reg, client: &http.Client{Timeout: 10 * time.Second}, alerter: alerter}
}

func (p *Prober) Run(ctx context.Context) {
	for {
		interval := p.reg.settings.Current().Routing.HealthCheckSec
		if interval > 0 {
			p.CheckAll(ctx)
		} else {
			interval = 30
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(interval) * time.Second):
		}
	}
}

func (p *Prober) CheckAll(ctx context.Context) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for _, d := range p.reg.AllDeployments() {
		if !d.Enabled {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(d *Deployment) {
			defer wg.Done()
			defer func() { <-sem }()
			p.Check(ctx, d)
		}(d)
	}
	wg.Wait()
}

// Check probes one deployment, updates its state, and emits transition alerts.
func (p *Prober) Check(ctx context.Context, d *Deployment) Health {
	start := time.Now()
	h := Health{Checked: start}
	err := p.probe(ctx, d, &h)
	h.LatencyMs = int(time.Since(start).Milliseconds())
	if err != nil {
		h.Error = err.Error()
	} else {
		h.Healthy = true
	}
	prev := d.health.Swap(&h)
	if prev != nil && prev.Healthy != h.Healthy {
		ev := hooks.Event{Kind: "deployment_up", Severity: "info", DedupeKey: "dep-up:" + d.ID,
			Title:  fmt.Sprintf("Deployment recovered: %s", d.Name),
			Body:   fmt.Sprintf("%s (%s) is healthy again.", d.Name, d.APIBase),
			Fields: map[string]string{"model": d.Name, "api_base": d.APIBase}}
		if !h.Healthy {
			ev = hooks.Event{Kind: "deployment_down", Severity: "critical", DedupeKey: "dep-down:" + d.ID,
				Title:  fmt.Sprintf("Deployment down: %s", d.Name),
				Body:   fmt.Sprintf("%s (%s) failed its health check: %s", d.Name, d.APIBase, h.Error),
				Fields: map[string]string{"model": d.Name, "api_base": d.APIBase, "error": h.Error}}
		}
		p.alerter.Emit(ev)
		slog.Info("deployment health changed", "model", d.Name, "api_base", d.APIBase, "healthy", h.Healthy, "error", h.Error)
	}
	if p.OnCheck != nil {
		p.OnCheck(d, h)
	}
	return h
}

func (p *Prober) probe(ctx context.Context, d *Deployment, h *Health) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, V1Base(d.APIBase)+"/models", nil)
	if d.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+d.APIKey)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET /v1/models returned %d", resp.StatusCode)
	}
	var lm struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &lm); err != nil {
		return fmt.Errorf("invalid /v1/models response")
	}
	for _, m := range lm.Data {
		h.Models = append(h.Models, m.ID)
	}
	if len(h.Models) > 0 {
		found := false
		for _, m := range h.Models {
			if m == d.UpstreamModel {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("upstream does not serve %q (serves: %s)", d.UpstreamModel, strings.Join(h.Models, ", "))
		}
	}
	return nil
}
