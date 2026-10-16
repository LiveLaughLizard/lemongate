// Package cacheui is the console area for the response cache: stats, settings, flush.
package cacheui

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"

	"lemongate/internal/auth"
	"lemongate/internal/cache"
	"lemongate/internal/settings"
	"lemongate/internal/ui"
)

const area = "cache"

type H struct {
	d *ui.Deps
	c *cache.Cache
}

// Mount registers routes for this area on the session-protected router.
func Mount(r chi.Router, d *ui.Deps, c *cache.Cache) {
	h := &H{d: d, c: c}
	r.Group(func(r chi.Router) {
		r.Use(ui.AdminWrites)
		r.Get("/ui/cache", h.index)
		r.Get("/ui/cache/stats", h.stats)
		r.Post("/ui/cache/settings", h.save)
		r.Post("/ui/cache/flush", h.flush)
		r.Post("/ui/cache/reset-stats", h.resetStats)
	})
}

type indexData struct {
	S       settings.Cache
	CanEdit bool
	BaseURL string
	MaxTTL  int
	Error   string
}

func (h *H) index(w http.ResponseWriter, r *http.Request) {
	p := auth.FromContext(r.Context())
	h.d.Render(w, r, "cache/index", "cache", "Response cache", indexData{S: h.d.Settings.Current().Cache, CanEdit: p.IsAdmin(),
		BaseURL: h.d.Cfg.BaseURL, MaxTTL: int(cache.MaxTTL.Seconds())})
}

type statsData struct {
	cache.Stats
	Enabled bool
	CanEdit bool
	Fill    float64
}

func (h *H) stats(w http.ResponseWriter, r *http.Request) {
	s := h.c.Stats(15)
	sd := statsData{Stats: s, Enabled: h.d.Settings.Current().Cache.Enabled, CanEdit: auth.FromContext(r.Context()).IsAdmin()}
	if s.MaxEntries > 0 {
		sd.Fill = float64(s.Entries) * 100 / float64(s.MaxEntries)
	}
	h.d.Partial(w, r, 200, area, "cache-stats", sd)
}

func (h *H) save(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	before := h.d.Settings.Current().Cache
	next := settings.Cache{
		Enabled:    ui.FormBool(r, "enabled"),
		TTLSeconds: ui.FormInt(r, "ttl_seconds", -1),
		MaxEntries: ui.FormInt(r, "max_entries", -1),
		PerKey:     ui.FormBool(r, "per_key"),
	}
	switch {
	case next.TTLSeconds < 1 || next.TTLSeconds > int(cache.MaxTTL.Seconds()):
		ui.Fail(w, 422, fmt.Sprintf("TTL must be between 1 and %d seconds", int(cache.MaxTTL.Seconds())))
		return
	case next.MaxEntries < 1 || next.MaxEntries > 1_000_000:
		ui.Fail(w, 422, "Max entries must be between 1 and 1,000,000")
		return
	}
	if _, err := h.d.Settings.Update(r.Context(), func(s *settings.Settings) { s.Cache = next }); err != nil {
		ui.Fail(w, 500, err.Error())
		return
	}
	h.d.Audit(r, "update", "settings", "cache", "Updated cache settings", before, next)
	msg := "Cache settings saved"
	if before.Enabled != next.Enabled {
		if next.Enabled {
			msg = "Response cache enabled"
		} else {
			msg = "Response cache disabled and flushed"
		}
	}
	ui.Toast(w, "success", msg)
	ui.Refresh(w, "refresh-cache")
	w.WriteHeader(http.StatusNoContent)
}

func (h *H) flush(w http.ResponseWriter, r *http.Request) {
	n := h.c.Flush()
	h.d.Audit(r, "flush", "cache", "", fmt.Sprintf("Flushed response cache (%d entries)", n), nil, nil)
	ui.Toast(w, "success", fmt.Sprintf("Flushed %s cached response%s", ui.Num(n), plural(n)))
	ui.Refresh(w, "refresh-cache")
	w.WriteHeader(http.StatusNoContent)
}

func (h *H) resetStats(w http.ResponseWriter, r *http.Request) {
	h.c.ResetStats()
	h.d.Audit(r, "reset_stats", "cache", "", "Reset response cache statistics", nil, nil)
	ui.Toast(w, "success", "Cache statistics reset")
	ui.Refresh(w, "refresh-cache")
	w.WriteHeader(http.StatusNoContent)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// Size formats a byte count for display (callable from templates as $.Data.Size n).
func (statsData) Size(v any) string {
	var n float64
	switch x := v.(type) {
	case int:
		n = float64(x)
	case int64:
		n = float64(x)
	}
	units := []string{"B", "KB", "MB", "GB"}
	i := 0
	for n >= 1024 && i < len(units)-1 {
		n /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f B", n)
	}
	return fmt.Sprintf("%.1f %s", n, units[i])
}

// Lookups is hits + misses.
func (s statsData) Lookups() int64 { return s.Hits + s.Misses }
