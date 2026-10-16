package session

import (
	"net/http"
	"net/url"
	"sync"
	"time"

	"lemongate/internal/auth"
)

// Sign-in throttling: failed attempts are counted per client IP and per account
// (email, or the master key), in fixed windows. It is in-memory and per replica.
const (
	throttleWindow     = 15 * time.Minute
	maxFailsPerIP      = 20
	maxFailsPerAccount = 10
)

type failWindow struct {
	count int
	reset time.Time
}

type throttle struct {
	mu   sync.Mutex
	fail map[string]*failWindow
}

var signIn = &throttle{fail: map[string]*failWindow{}}

// blocked reports how long until any of keys may try again (0 = allowed).
func (t *throttle) blocked(keys map[string]int) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	var wait time.Duration
	for k, limit := range keys {
		if w := t.fail[k]; w != nil && now.Before(w.reset) && w.count >= limit {
			wait = max(wait, w.reset.Sub(now))
		}
	}
	return wait
}

func (t *throttle) failed(keys ...string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	if len(t.fail) > 50000 {
		for k, w := range t.fail {
			if now.After(w.reset) {
				delete(t.fail, k)
			}
		}
	}
	for _, k := range keys {
		w := t.fail[k]
		if w == nil || now.After(w.reset) {
			w = &failWindow{reset: now.Add(throttleWindow)}
			t.fail[k] = w
		}
		w.count++
	}
}

func (t *throttle) succeeded(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.fail, key)
}

// dummyHash is compared against when an account does not exist, so a failed sign-in
// takes as long for unknown emails as for wrong passwords.
var dummyHash = func() string {
	h, _ := auth.HashPassword("lemongate-timing-equalizer")
	return h
}()

// crossSite reports a cross-origin form post (login CSRF). Browsers send Origin and/or
// Sec-Fetch-Site on POSTs; requests without either (non-browser clients) are allowed.
// The origin may match the request host or the configured public base URL.
func crossSite(r *http.Request, baseURL string) bool {
	if s := r.Header.Get("Sec-Fetch-Site"); s == "cross-site" {
		return true
	}
	o := r.Header.Get("Origin")
	if o == "" {
		return false
	}
	u, err := url.Parse(o)
	if err != nil || u.Host == "" {
		return true
	}
	if u.Host == r.Host {
		return false
	}
	b, err := url.Parse(baseURL)
	return err != nil || u.Host != b.Host
}
