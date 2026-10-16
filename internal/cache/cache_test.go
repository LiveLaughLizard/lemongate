package cache

import (
	"encoding/json"
	"testing"
	"time"

	"lemongate/internal/auth"
	"lemongate/internal/hooks"
	"lemongate/internal/store"
)

func info(keyID string) hooks.CallInfo {
	return hooks.CallInfo{Route: "chat/completions", Model: "llama", Principal: &auth.Principal{Kind: "key", Key: &store.Key{ID: keyID}}}
}

func TestKeyCanonicalAndScoped(t *testing.T) {
	c := New(nil)
	var a, b map[string]any
	_ = json.Unmarshal([]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}],"temperature":0.7}`), &a)
	_ = json.Unmarshal([]byte(`{"temperature":0.7,"messages":[{"content":"hi","role":"user"}],"model":"m"}`), &b)
	ka, ok := c.Key(info("k1"), a)
	if !ok {
		t.Fatal("expected cacheable")
	}
	kb, _ := c.Key(info("k1"), b)
	if ka != kb {
		t.Fatal("key order must not change the cache key")
	}
	// settings == nil behaves as per-key scoping.
	if kc, _ := c.Key(info("k2"), a); kc == ka {
		t.Fatal("different keys must not share entries")
	}
	i := info("k1")
	i.Model = "other"
	if kd, _ := c.Key(i, a); kd == ka {
		t.Fatal("model must be part of the key")
	}
}

func TestNotCacheable(t *testing.T) {
	c := New(nil)
	for _, tc := range []struct {
		route string
		body  map[string]any
	}{
		{"chat/completions", map[string]any{"stream": true}},
		{"chat/completions", map[string]any{"n": json.Number("2")}},
		{"chat/completions", map[string]any{"n": 3.0}},
		{"responses", map[string]any{"input": "x"}},
		{"audio/transcriptions", map[string]any{}},
	} {
		i := info("k")
		i.Route = tc.route
		if _, ok := c.Key(i, tc.body); ok {
			t.Errorf("%s %v should not be cacheable", tc.route, tc.body)
		}
	}
	i := info("k")
	i.Route = "embeddings"
	if _, ok := c.Key(i, map[string]any{"input": "x", "n": 1.0}); !ok {
		t.Error("embeddings should be cacheable")
	}
}

func TestGetSetTTLAndStats(t *testing.T) {
	c := New(nil)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	k, _ := c.Key(info("k"), map[string]any{"messages": "x"})
	if _, ok := c.Get(k); ok {
		t.Fatal("unexpected hit")
	}
	c.Set(k, []byte(`{"ok":true}`), time.Minute)
	if b, ok := c.Get(k); !ok || string(b) != `{"ok":true}` {
		t.Fatal("expected hit")
	}
	s := c.Stats(10)
	if s.Hits != 1 || s.Misses != 1 || s.Entries != 1 || s.Bytes != 11 || s.HitRate != 50 {
		t.Fatalf("stats = %+v", s)
	}
	if len(s.Models) != 1 || s.Models[0].Model != "llama" || s.Models[0].Hits != 1 || s.Models[0].Entries != 1 {
		t.Fatalf("model stats = %+v", s.Models)
	}
	if len(s.Recent) != 1 || s.Recent[0].Hits != 1 || s.Recent[0].Route != "chat/completions" {
		t.Fatalf("recent = %+v", s.Recent)
	}
	// Replacing keeps byte accounting exact.
	c.Set(k, []byte(`{}`), time.Minute)
	if s := c.Stats(0); s.Bytes != 2 {
		t.Fatalf("bytes after replace = %d", s.Bytes)
	}
	now = now.Add(2 * time.Minute)
	if _, ok := c.Get(k); ok {
		t.Fatal("expired entry served")
	}
	if s := c.Stats(0); s.Entries != 0 || s.Bytes != 0 {
		t.Fatalf("after expiry = %+v", s)
	}
}

func TestMaxTTLAndFlush(t *testing.T) {
	c := New(nil)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	c.Set("m\x00r\x00a", []byte("1"), 100*time.Hour)
	c.Set("m\x00r\x00b", []byte("2"), time.Hour)
	if e := c.Stats(1).Recent[0]; e.Expires.Sub(e.Created) > MaxTTL {
		t.Fatalf("ttl not capped: %v", e.Expires.Sub(e.Created))
	}
	if n := c.Flush(); n != 2 {
		t.Fatalf("flushed %d", n)
	}
	if s := c.Stats(0); s.Entries != 0 || s.Bytes != 0 {
		t.Fatalf("after flush = %+v", s)
	}
}

func TestResizeEvicts(t *testing.T) {
	c := New(nil)
	for _, k := range []string{"a", "b", "c", "d"} {
		c.Set("m\x00r\x00"+k, []byte(k), time.Hour)
	}
	c.resize(2)
	s := c.Stats(0)
	if s.Entries != 2 || s.MaxEntries != 2 || s.Evictions != 2 || s.Bytes != 2 {
		t.Fatalf("after resize = %+v", s)
	}
	if _, ok := c.Get("m\x00r\x00d"); !ok {
		t.Fatal("newest entry should survive")
	}
}

func TestSessionsScopedByUser(t *testing.T) {
	c := New(nil)
	body := map[string]any{"messages": "x"}
	key := func(p *auth.Principal) string {
		k, ok := c.Key(hooks.CallInfo{Route: "chat/completions", Model: "llama", Principal: p}, body)
		if !ok {
			t.Fatal("expected cacheable")
		}
		return k
	}
	alice := key(&auth.Principal{Kind: "session", User: &store.User{ID: "u1"}})
	bob := key(&auth.Principal{Kind: "session", User: &store.User{ID: "u2"}})
	if alice == bob {
		t.Fatal("different console users must not share entries")
	}
	if again := key(&auth.Principal{Kind: "session", User: &store.User{ID: "u1"}}); again != alice {
		t.Fatal("same user should hit the same entry")
	}
	if key(&auth.Principal{Kind: "session", Role: auth.RoleAdmin}) != key(&auth.Principal{Kind: "master"}) {
		t.Fatal("master session and master key share a scope")
	}
	if key(&auth.Principal{Kind: "master"}) == alice {
		t.Fatal("master must not share a user's entries")
	}
}
