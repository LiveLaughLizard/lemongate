// Package cache is an in-memory, exact-match response cache.
//
// Keys are a SHA-256 over the route, the resolved model group, the caller (API key
// or console user, when settings.cache.per_key is on) and the canonical JSON of the
// request body after gateway-only fields were stripped and guardrails ran.
// Canonical means object keys are sorted (encoding/json sorts map keys), so
// semantically equal requests that only differ in key order share an entry.
//
// What is cached: non-streaming chat/completions, completions, embeddings, rerank
// and score responses. Not cached: streaming requests, requests asking for several
// choices (n > 1) and the stateful responses API. Sampling temperature is not
// considered: a cached answer is a recorded sample, which callers can bypass with
// "Cache-Control: no-cache" (skip lookup) or "no-store" (do not save).
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"

	"lemongate/internal/auth"
	"lemongate/internal/hooks"
	"lemongate/internal/settings"
)

// MaxTTL caps any entry's lifetime, including per-request x-lemongate-cache-ttl overrides.
const MaxTTL = 24 * time.Hour

// DefaultMaxEntries is used when settings carry no positive limit.
const DefaultMaxEntries = 5000

// Routes whose responses may be cached.
var cacheableRoutes = map[string]bool{
	"chat/completions": true, "completions": true, "embeddings": true, "rerank": true, "score": true,
}

type entry struct {
	model   string
	route   string
	body    []byte
	created time.Time
	expires time.Time
	hits    *atomic.Int64
}

type modelCounters struct{ hits, misses atomic.Int64 }

// Cache implements hooks.Cache.
type Cache struct {
	settings *settings.Store

	mu      sync.Mutex // guards lru swaps, size and lastSweep
	lru     *expirable.LRU[string, entry]
	size    int
	lastSwp time.Time

	hits, misses, sets, evictions atomic.Int64
	bytes                         atomic.Int64
	models                        sync.Map // model -> *modelCounters
	since                         atomic.Pointer[time.Time]
	now                           func() time.Time
}

func New(st *settings.Store) *Cache {
	c := &Cache{settings: st, now: time.Now}
	c.lru = c.newLRU(c.maxEntries())
	c.resetSince()
	if st != nil {
		st.OnChange(func(s settings.Settings) {
			c.resize(s.Cache.MaxEntries)
			if !s.Cache.Enabled {
				c.Flush()
			}
		})
	}
	return c
}

func (c *Cache) resetSince() {
	t := c.now()
	c.since.Store(&t)
}

func (c *Cache) maxEntries() int {
	if c.settings != nil {
		if n := c.settings.Current().Cache.MaxEntries; n > 0 {
			return n
		}
	}
	return DefaultMaxEntries
}

func (c *Cache) newLRU(size int) *expirable.LRU[string, entry] {
	c.size = size
	// TTL 0 disables the library's background expiry; entries carry their own
	// deadline (per-request TTLs differ) and are dropped lazily plus by sweep().
	return expirable.NewLRU[string, entry](size, func(_ string, e entry) {
		c.bytes.Add(-int64(len(e.body)))
	}, 0)
}

func (c *Cache) resize(n int) {
	if n <= 0 {
		n = DefaultMaxEntries
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if n == c.size {
		return
	}
	c.size = n
	if ev := c.lru.Resize(n); ev > 0 {
		c.evictions.Add(int64(ev))
	}
}

// Key returns the cache key for a call, or false when the call is not cacheable.
func (c *Cache) Key(info hooks.CallInfo, body map[string]any) (string, bool) {
	if !cacheableRoutes[info.Route] || info.Stream {
		return "", false
	}
	if s, ok := body["stream"].(bool); ok && s {
		return "", false
	}
	if n, ok := number(body["n"]); ok && n > 1 {
		return "", false
	}
	canon, err := json.Marshal(body)
	if err != nil {
		return "", false
	}
	scope := ""
	if c.settings == nil || c.settings.Current().Cache.PerKey {
		scope = principalScope(info.Principal)
	}
	h := sha256.New()
	for _, part := range []string{info.Route, info.Model, scope} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	h.Write(canon)
	// The model and route ride along in the key so lookups can be attributed.
	return info.Model + "\x00" + info.Route + "\x00" + hex.EncodeToString(h.Sum(nil)), true
}

// principalScope partitions per-key caching: API keys by id, console sessions by
// user (so users never share playground answers), master credentials together.
func principalScope(p *auth.Principal) string {
	switch {
	case p == nil:
		return ""
	case p.KeyID() != "":
		return p.KeyID()
	case p.UserID() != "":
		return "user:" + p.UserID()
	case p.Kind == "master" || p.Kind == "session":
		return "master" // sessions without a user are master-key logins
	}
	return p.Kind
}

func splitKey(key string) (model, route string) {
	parts := strings.SplitN(key, "\x00", 3)
	if len(parts) == 3 {
		return parts[0], parts[1]
	}
	return "", ""
}

func number(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(n, 64)
		return f, err == nil
	}
	return 0, false
}

func (c *Cache) counters(model string) *modelCounters {
	if v, ok := c.models.Load(model); ok {
		return v.(*modelCounters)
	}
	v, _ := c.models.LoadOrStore(model, &modelCounters{})
	return v.(*modelCounters)
}

func (c *Cache) current() *expirable.LRU[string, entry] {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru
}

// Get returns a stored response body. Every call counts as a hit or a miss.
func (c *Cache) Get(key string) ([]byte, bool) {
	model, _ := splitKey(key)
	lru := c.current()
	e, ok := lru.Get(key)
	if ok && !c.now().Before(e.expires) {
		lru.Remove(key)
		ok = false
	}
	if !ok {
		c.misses.Add(1)
		c.counters(model).misses.Add(1)
		return nil, false
	}
	c.hits.Add(1)
	c.counters(model).hits.Add(1)
	e.hits.Add(1)
	return e.body, true
}

// Set stores a response body for ttl (capped at MaxTTL; <= 0 uses the settings TTL).
func (c *Cache) Set(key string, value []byte, ttl time.Duration) {
	if ttl <= 0 && c.settings != nil {
		ttl = time.Duration(c.settings.Current().Cache.TTLSeconds) * time.Second
	}
	if ttl <= 0 {
		return
	}
	ttl = min(ttl, MaxTTL)
	model, route := splitKey(key)
	now := c.now()
	body := append([]byte(nil), value...)
	lru := c.current()
	if old, ok := lru.Peek(key); ok { // replacing does not fire the evict callback
		c.bytes.Add(-int64(len(old.body)))
	}
	c.bytes.Add(int64(len(body)))
	if lru.Add(key, entry{model: model, route: route, body: body, created: now, expires: now.Add(ttl), hits: new(atomic.Int64)}) {
		c.evictions.Add(1)
	}
	c.sets.Add(1)
	c.maybeSweep()
}

// maybeSweep drops expired entries at most once a minute so they do not hold memory.
func (c *Cache) maybeSweep() {
	c.mu.Lock()
	if c.now().Sub(c.lastSwp) < time.Minute {
		c.mu.Unlock()
		return
	}
	c.lastSwp = c.now()
	lru := c.lru
	c.mu.Unlock()
	c.sweep(lru)
}

func (c *Cache) sweep(lru *expirable.LRU[string, entry]) int {
	now := c.now()
	n := 0
	for _, k := range lru.Keys() {
		if e, ok := lru.Peek(k); ok && !now.Before(e.expires) {
			if lru.Remove(k) {
				n++
			}
		}
	}
	return n
}

// Flush drops every entry and returns how many were removed.
func (c *Cache) Flush() int {
	lru := c.current()
	n := lru.Len()
	lru.Purge()
	return n
}

// ResetStats zeroes hit/miss counters.
func (c *Cache) ResetStats() {
	c.hits.Store(0)
	c.misses.Store(0)
	c.sets.Store(0)
	c.evictions.Store(0)
	c.models.Range(func(k, _ any) bool { c.models.Delete(k); return true })
	c.resetSince()
}

// ModelStats are per-model lookup counters.
type ModelStats struct {
	Model   string
	Hits    int64
	Misses  int64
	HitRate float64
	Entries int
	Bytes   int64
}

// EntryInfo describes one cached response.
type EntryInfo struct {
	Model   string
	Route   string
	Bytes   int
	Hits    int64
	Created time.Time
	Expires time.Time
}

// Stats is a point-in-time snapshot.
type Stats struct {
	Hits, Misses, Sets, Evictions int64
	HitRate                       float64 // percent
	Entries, MaxEntries           int
	Bytes                         int64
	Since                         time.Time
	Models                        []ModelStats
	Recent                        []EntryInfo // newest first
}

// Stats returns counters, per-model breakdown and the most recent entries.
func (c *Cache) Stats(recent int) Stats {
	lru := c.current()
	c.sweep(lru)
	c.mu.Lock()
	maxN := c.size
	c.mu.Unlock()
	s := Stats{Hits: c.hits.Load(), Misses: c.misses.Load(), Sets: c.sets.Load(), Evictions: c.evictions.Load(),
		Entries: lru.Len(), MaxEntries: maxN, Bytes: max(c.bytes.Load(), 0), Since: *c.since.Load()}
	s.HitRate = rate(s.Hits, s.Misses)

	per := map[string]*ModelStats{}
	get := func(m string) *ModelStats {
		if per[m] == nil {
			per[m] = &ModelStats{Model: m}
		}
		return per[m]
	}
	c.models.Range(func(k, v any) bool {
		mc := v.(*modelCounters)
		ms := get(k.(string))
		ms.Hits, ms.Misses = mc.hits.Load(), mc.misses.Load()
		return true
	})
	var all []EntryInfo
	for _, e := range lru.Values() {
		ms := get(e.model)
		ms.Entries++
		ms.Bytes += int64(len(e.body))
		all = append(all, EntryInfo{Model: e.model, Route: e.route, Bytes: len(e.body), Hits: e.hits.Load(), Created: e.created, Expires: e.expires})
	}
	for _, ms := range per {
		ms.HitRate = rate(ms.Hits, ms.Misses)
		s.Models = append(s.Models, *ms)
	}
	sort.Slice(s.Models, func(i, j int) bool {
		a, b := s.Models[i], s.Models[j]
		if a.Hits+a.Misses != b.Hits+b.Misses {
			return a.Hits+a.Misses > b.Hits+b.Misses
		}
		return a.Model < b.Model
	})
	sort.Slice(all, func(i, j int) bool { return all[i].Created.After(all[j].Created) })
	if recent > 0 && len(all) > recent {
		all = all[:recent]
	}
	s.Recent = all
	return s
}

func rate(h, m int64) float64 {
	if h+m == 0 {
		return 0
	}
	return float64(h) * 100 / float64(h+m)
}
