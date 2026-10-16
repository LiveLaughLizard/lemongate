// Package playground is the in-console chat and embeddings tester. The browser
// calls the gateway's /v1 endpoints directly with the session cookie + CSRF header,
// so requests are authorized, routed, logged and billed like any other client.
package playground

import (
	"net/http"
	"slices"

	"github.com/go-chi/chi/v5"

	"lemongate/internal/auth"
	"lemongate/internal/ui"
)

type H struct{ d *ui.Deps }

func Mount(r chi.Router, d *ui.Deps) {
	h := &H{d}
	r.Get("/ui/playground", h.index)
}

// ModelInfo is what the client needs to drive the model picker and cost readout.
type ModelInfo struct {
	Name           string  `json:"name"`
	Mode           string  `json:"mode"`
	Description    string  `json:"description"`
	ContextWindow  int     `json:"context_window"`
	MaxOutput      int     `json:"max_output"`
	InputCostPerM  float64 `json:"input_cost_per_m"`
	OutputCostPerM float64 `json:"output_cost_per_m"`
	Healthy        int     `json:"healthy"`
	Replicas       int     `json:"replicas"`
}

type pageData struct {
	Chat      []ModelInfo `json:"chat"`
	Embedding []ModelInfo `json:"embedding"`
	Model     string      `json:"model"`
	Tab       string      `json:"tab"`
	BaseURL   string      `json:"base_url"`
	Total     int         `json:"-"`
	CanModels bool        `json:"-"`
}

func (h *H) index(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	allowed := p.AllowedModels(h.d.Registry)
	data := pageData{Model: r.URL.Query().Get("model"), Tab: r.URL.Query().Get("tab"), BaseURL: h.d.Cfg.BaseURL + "/v1",
		Total: len(h.d.Registry.AllModelNames()), CanModels: p.CanViewAll()}
	for _, g := range h.d.Registry.Groups() {
		if allowed != nil && !slices.Contains(allowed, g.Name) {
			continue
		}
		mi := ModelInfo{Name: g.Name, Mode: g.Mode, Description: g.Description, InputCostPerM: g.InputCostPerM, OutputCostPerM: g.OutputCostPerM,
			Healthy: g.Healthy}
		for _, d := range g.Deployments {
			if d.Enabled {
				mi.Replicas++
			}
		}
		if g.ContextWindow != nil {
			mi.ContextWindow = *g.ContextWindow
		}
		if g.MaxOutputTokens != nil {
			mi.MaxOutput = *g.MaxOutputTokens
		}
		switch g.Mode {
		case "embedding":
			data.Embedding = append(data.Embedding, mi)
		case "", "chat", "completion":
			if mi.Mode == "" {
				mi.Mode = "chat"
			}
			data.Chat = append(data.Chat, mi)
		}
	}
	// Resolve an alias in ?model= to its group so the picker can select it.
	if data.Model != "" {
		data.Model = h.d.Registry.Resolve(data.Model)
	}
	if data.Tab != "embeddings" || len(data.Embedding) == 0 {
		data.Tab = "chat"
		if len(data.Chat) == 0 && len(data.Embedding) > 0 {
			data.Tab = "embeddings"
		}
	}
	h.d.Render(w, r, "playground/index", "playground", "Playground", data)
}
