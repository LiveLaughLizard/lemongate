// Package routing keeps the live view of model groups and their deployments,
// chooses a deployment per request, and tracks deployment health.
package routing

import (
	"context"
	"math/rand/v2"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"lemongate/internal/config"
	"lemongate/internal/secret"
	"lemongate/internal/settings"
	"lemongate/internal/store"
)

// Deployment is a routable upstream with live counters.
type Deployment struct {
	store.Deployment

	inflight   atomic.Int64
	latencyEW  atomic.Int64 // EWMA latency in microseconds
	mu         sync.Mutex
	failures   []time.Time
	coolUntil  time.Time
	minute     int64
	minuteReqs int
	minuteToks int

	health atomic.Pointer[Health]
}

type Health struct {
	Healthy   bool      `json:"healthy"`
	Checked   time.Time `json:"checked"`
	LatencyMs int       `json:"latency_ms"`
	Error     string    `json:"error"`
	Models    []string  `json:"models"`
}

func (d *Deployment) InFlight() int64 { return d.inflight.Load() }

func (d *Deployment) LatencyMs() float64 { return float64(d.latencyEW.Load()) / 1000 }

func (d *Deployment) Health() *Health { return d.health.Load() }

func (d *Deployment) CoolingDown() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return time.Now().Before(d.coolUntil)
}

func (d *Deployment) CooldownRemaining() time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	return time.Until(d.coolUntil)
}

// MinuteUsage returns requests and tokens used in the current minute.
func (d *Deployment) MinuteUsage() (int, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.minute != time.Now().Unix()/60 {
		return 0, 0
	}
	return d.minuteReqs, d.minuteToks
}

func (d *Deployment) Begin() {
	d.inflight.Add(1)
	d.mu.Lock()
	now := time.Now().Unix() / 60
	if d.minute != now {
		d.minute, d.minuteReqs, d.minuteToks = now, 0, 0
	}
	d.minuteReqs++
	d.mu.Unlock()
}

// End records the outcome of a call that began with Begin.
func (d *Deployment) End(ok bool, latency time.Duration, tokens int, rs settings.Routing) {
	d.inflight.Add(-1)
	d.mu.Lock()
	defer d.mu.Unlock()
	if tokens > 0 && d.minute == time.Now().Unix()/60 {
		d.minuteToks += tokens
	}
	if ok {
		alpha := rs.LatencyEWMAAlpha
		if alpha <= 0 || alpha > 1 {
			alpha = 0.3
		}
		cur := d.latencyEW.Load()
		us := latency.Microseconds()
		if cur == 0 {
			d.latencyEW.Store(us)
		} else {
			d.latencyEW.Store(int64(alpha*float64(us) + (1-alpha)*float64(cur)))
		}
		return
	}
	now := time.Now()
	d.failures = append(d.failures, now)
	cut := now.Add(-time.Minute)
	d.failures = slices.DeleteFunc(d.failures, func(t time.Time) bool { return t.Before(cut) })
	if rs.CooldownFailures > 0 && len(d.failures) >= rs.CooldownFailures {
		d.coolUntil = now.Add(time.Duration(rs.CooldownSeconds) * time.Second)
		d.failures = nil
	}
}

func (d *Deployment) ClearCooldown() {
	d.mu.Lock()
	d.coolUntil = time.Time{}
	d.failures = nil
	d.mu.Unlock()
}

func (d *Deployment) atCapacity() bool {
	if d.MaxParallel != nil && *d.MaxParallel > 0 && d.inflight.Load() >= int64(*d.MaxParallel) {
		return true
	}
	reqs, toks := d.MinuteUsage()
	if d.RPMLimit != nil && *d.RPMLimit > 0 && reqs >= *d.RPMLimit {
		return true
	}
	return d.TPMLimit != nil && *d.TPMLimit > 0 && toks >= *d.TPMLimit
}

// Registry is the routing table. It is rebuilt wholesale on Reload, carrying
// live counters over for deployments that still exist.
type Registry struct {
	store    *store.Store
	box      *secret.Box
	file     config.FileConfig
	settings *settings.Store

	mu           sync.RWMutex
	groups       map[string][]*Deployment
	byID         map[string]*Deployment
	aliases      map[string]string
	accessGroups map[string][]string
	fallbacks    map[string][]string
	ctxFallbacks map[string][]string
}

func NewRegistry(s *store.Store, box *secret.Box, file config.FileConfig, st *settings.Store) *Registry {
	return &Registry{store: s, box: box, file: file, settings: st, groups: map[string][]*Deployment{}, byID: map[string]*Deployment{}}
}

func (r *Registry) Reload(ctx context.Context) error {
	deps, err := r.store.ListDeployments(ctx)
	if err != nil {
		return err
	}
	creds, err := r.store.ListCredentials(ctx)
	if err != nil {
		return err
	}
	credSecret := map[string]string{}
	for _, c := range creds {
		if v, err := r.box.OpenString(c.SecretEnc); err == nil {
			credSecret[c.ID] = v
		}
	}
	for i := range deps {
		if deps[i].CredentialID != nil {
			deps[i].APIKey = credSecret[*deps[i].CredentialID]
		}
	}
	for i, m := range r.file.Models {
		d := store.Deployment{
			ID: "config-" + itoa(i), Name: m.Name, APIBase: m.APIBase, UpstreamModel: m.UpstreamModel, Mode: m.Mode,
			Weight: m.Weight, MaxParallel: m.MaxParallel, TimeoutSeconds: m.TimeoutSeconds, ContextWindow: m.ContextWindow,
			MaxOutputTokens: m.MaxOutputTokens, InputCostPerM: m.InputCostPerM, OutputCostPerM: m.OutputCostPerM,
			Description: m.Description, Tags: m.Tags, ExtraHeaders: m.ExtraHeaders, Enabled: true, FromConfig: true, APIKey: m.APIKey,
		}
		d.RPMLimit, d.TPMLimit = m.RPMLimit, m.TPMLimit
		if d.UpstreamModel == "" {
			d.UpstreamModel = d.Name
		}
		if d.Mode == "" {
			d.Mode = "chat"
		}
		if d.Weight <= 0 {
			d.Weight = 1
		}
		if d.TimeoutSeconds <= 0 {
			d.TimeoutSeconds = 600
		}
		deps = append(deps, d)
	}

	aliases := map[string]string{}
	for k, v := range r.file.Aliases {
		aliases[k] = v
	}
	if as, err := r.store.ListAliases(ctx); err == nil {
		for _, a := range as {
			aliases[a.Alias] = a.Target
		}
	}
	groupsAG := map[string][]string{}
	for k, v := range r.file.AccessGroups {
		groupsAG[k] = v
	}
	if ag, err := r.store.ListAccessGroups(ctx); err == nil {
		for _, g := range ag {
			groupsAG[g.Name] = g.Models
		}
	}
	fb := map[string][]string{}
	cfb := map[string][]string{}
	for k, v := range r.file.Fallbacks {
		fb[k] = v
	}
	for k, v := range r.file.ContextFallbacks {
		cfb[k] = v
	}
	if fs, err := r.store.ListFallbacks(ctx); err == nil {
		for _, f := range fs {
			if f.Kind == "context" {
				cfb[f.Model] = f.Targets
			} else {
				fb[f.Model] = f.Targets
			}
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	groups := map[string][]*Deployment{}
	byID := map[string]*Deployment{}
	for _, d := range deps {
		nd := &Deployment{Deployment: d}
		if old, ok := r.byID[d.ID]; ok {
			nd.latencyEW.Store(old.latencyEW.Load())
			nd.inflight.Store(old.inflight.Load())
			nd.health.Store(old.health.Load())
			old.mu.Lock()
			nd.coolUntil, nd.failures = old.coolUntil, old.failures
			nd.minute, nd.minuteReqs, nd.minuteToks = old.minute, old.minuteReqs, old.minuteToks
			old.mu.Unlock()
		}
		byID[d.ID] = nd
		groups[d.Name] = append(groups[d.Name], nd)
	}
	r.groups, r.byID, r.aliases, r.accessGroups, r.fallbacks, r.ctxFallbacks = groups, byID, aliases, groupsAG, fb, cfb
	return nil
}

func itoa(i int) string {
	const digits = "0123456789"
	if i < 10 {
		return digits[i : i+1]
	}
	return itoa(i/10) + digits[i%10:i%10+1]
}

// Resolve maps an alias to its model group name (identity if not an alias).
func (r *Registry) Resolve(name string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for i := 0; i < 5; i++ {
		t, ok := r.aliases[name]
		if !ok {
			break
		}
		name = t
	}
	return name
}

func (r *Registry) HasGroup(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.groups[name]) > 0
}

// AllModelNames lists every model group name, sorted.
func (r *Registry) AllModelNames() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.groups))
	for k := range r.groups {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (r *Registry) Aliases() map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]string, len(r.aliases))
	for k, v := range r.aliases {
		out[k] = v
	}
	return out
}

func (r *Registry) AccessGroupNames() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.accessGroups))
	for k := range r.accessGroups {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (r *Registry) ExpandAccessGroups(names []string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []string
	for _, n := range names {
		out = append(out, r.accessGroups[n]...)
	}
	return out
}

func (r *Registry) Fallbacks(model string, context bool) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if context {
		return slices.Clone(r.ctxFallbacks[model])
	}
	return slices.Clone(r.fallbacks[model])
}

// Group returns a snapshot of the deployments in a model group.
func (r *Registry) Group(name string) []*Deployment {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Clone(r.groups[name])
}

func (r *Registry) Deployment(id string) *Deployment {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byID[id]
}

func (r *Registry) AllDeployments() []*Deployment {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Deployment, 0, len(r.byID))
	for _, d := range r.byID {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// GroupInfo summarizes a model group for listings.
type GroupInfo struct {
	Name            string
	Mode            string
	Deployments     []*Deployment
	Healthy         int
	Description     string
	ContextWindow   *int
	MaxOutputTokens *int
	InputCostPerM   float64
	OutputCostPerM  float64
	Tags            []string
}

func (r *Registry) Groups() []GroupInfo {
	var out []GroupInfo
	for _, name := range r.AllModelNames() {
		deps := r.Group(name)
		gi := GroupInfo{Name: name, Deployments: deps}
		for _, d := range deps {
			if gi.Mode == "" {
				gi.Mode = d.Mode
			}
			if gi.Description == "" {
				gi.Description = d.Description
			}
			if gi.ContextWindow == nil {
				gi.ContextWindow = d.ContextWindow
			}
			if gi.MaxOutputTokens == nil {
				gi.MaxOutputTokens = d.MaxOutputTokens
			}
			if gi.InputCostPerM == 0 {
				gi.InputCostPerM, gi.OutputCostPerM = d.InputCostPerM, d.OutputCostPerM
			}
			for _, t := range d.Tags {
				if !slices.Contains(gi.Tags, t) {
					gi.Tags = append(gi.Tags, t)
				}
			}
			if d.Enabled && !d.CoolingDown() && (d.Health() == nil || d.Health().Healthy) {
				gi.Healthy++
			}
		}
		out = append(out, gi)
	}
	return out
}

// Pick chooses a deployment from the group, skipping excluded IDs, disabled,
// cooling-down, unhealthy and saturated deployments when alternatives exist.
func (r *Registry) Pick(group string, exclude map[string]bool) *Deployment {
	deps := r.Group(group)
	var cands []*Deployment
	for _, d := range deps {
		if d.Enabled && !exclude[d.ID] {
			cands = append(cands, d)
		}
	}
	if len(cands) == 0 {
		return nil
	}
	filter := func(keep func(*Deployment) bool) {
		var next []*Deployment
		for _, d := range cands {
			if keep(d) {
				next = append(next, d)
			}
		}
		if len(next) > 0 {
			cands = next
		}
	}
	filter(func(d *Deployment) bool { return !d.CoolingDown() })
	filter(func(d *Deployment) bool { h := d.Health(); return h == nil || h.Healthy })
	filter(func(d *Deployment) bool { return !d.atCapacity() })
	return choose(r.settings.Current().Routing.Strategy, cands)
}

func choose(strategy string, cands []*Deployment) *Deployment {
	if len(cands) == 1 {
		return cands[0]
	}
	switch strategy {
	case "least_busy":
		return minBy(cands, func(d *Deployment) float64 { return float64(d.InFlight()) })
	case "latency":
		// Unmeasured deployments get priority so they get sampled.
		return minBy(cands, func(d *Deployment) float64 { return d.LatencyMs() })
	case "usage":
		return minBy(cands, func(d *Deployment) float64 { _, t := d.MinuteUsage(); return float64(t) })
	}
	total := 0
	for _, d := range cands {
		total += max(d.Weight, 1)
	}
	n := rand.IntN(total)
	for _, d := range cands {
		n -= max(d.Weight, 1)
		if n < 0 {
			return d
		}
	}
	return cands[len(cands)-1]
}

func minBy(cands []*Deployment, f func(*Deployment) float64) *Deployment {
	best := []*Deployment{cands[0]}
	bv := f(cands[0])
	for _, d := range cands[1:] {
		v := f(d)
		switch {
		case v < bv:
			best, bv = []*Deployment{d}, v
		case v == bv:
			best = append(best, d)
		}
	}
	return best[rand.IntN(len(best))]
}
