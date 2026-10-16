// Package limits enforces per-entity request rate, token rate and concurrency limits.
// State is in-process: a single gateway replica is assumed.
package limits

import (
	"fmt"
	"sync"
	"time"
)

// Subject identifies a limited entity, e.g. "key:<id>", "user:<id>", "team:<id>".
type Subject struct {
	ID          string
	Label       string
	RPM         *int
	TPM         *int
	MaxParallel *int
}

type window struct {
	minute   int64
	reqs     int
	toks     int
	prevReqs int
	prevToks int
	inflight int
}

// estimate approximates a sliding 60s window by weighting the previous minute.
func (w *window) roll(now time.Time) (reqs, toks float64) {
	m := now.Unix() / 60
	switch {
	case w.minute == m:
	case w.minute == m-1:
		w.prevReqs, w.prevToks, w.reqs, w.toks, w.minute = w.reqs, w.toks, 0, 0, m
	default:
		w.prevReqs, w.prevToks, w.reqs, w.toks, w.minute = 0, 0, 0, 0, m
	}
	frac := 1 - float64(now.Unix()%60)/60
	return float64(w.reqs) + float64(w.prevReqs)*frac, float64(w.toks) + float64(w.prevToks)*frac
}

type Limiter struct {
	mu   sync.Mutex
	wins map[string]*window
	// Rejections counts limit hits by kind, for metrics.
	OnReject func(kind string)
}

func New() *Limiter { return &Limiter{wins: map[string]*window{}} }

type LimitError struct {
	Subject string
	Kind    string // rpm | tpm | parallel
	Limit   int
	Retry   time.Duration
}

func (e *LimitError) Error() string {
	switch e.Kind {
	case "parallel":
		return fmt.Sprintf("%s has reached its limit of %d parallel requests", e.Subject, e.Limit)
	case "tpm":
		return fmt.Sprintf("%s has exceeded its limit of %d tokens per minute", e.Subject, e.Limit)
	}
	return fmt.Sprintf("%s has exceeded its limit of %d requests per minute", e.Subject, e.Limit)
}

// Remaining reports the tightest remaining rpm/tpm across subjects (-1 = unlimited).
type Remaining struct{ Requests, Tokens int }

// Acquire checks every subject atomically and, if all pass, counts the request and
// increments in-flight counters. Call the returned release func when the request ends.
func (l *Limiter) Acquire(subjects []Subject) (release func(tokens int), rem Remaining, err error) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	rem = Remaining{-1, -1}
	for _, s := range subjects {
		w := l.win(s.ID)
		reqs, toks := w.roll(now)
		retry := time.Duration(60-now.Unix()%60) * time.Second
		if s.MaxParallel != nil && *s.MaxParallel > 0 && w.inflight >= *s.MaxParallel {
			l.reject("parallel")
			return nil, rem, &LimitError{s.Label, "parallel", *s.MaxParallel, time.Second}
		}
		if s.RPM != nil && *s.RPM > 0 {
			if reqs >= float64(*s.RPM) {
				l.reject("rpm")
				return nil, rem, &LimitError{s.Label, "rpm", *s.RPM, retry}
			}
			rem.Requests = minRem(rem.Requests, *s.RPM-int(reqs)-1)
		}
		if s.TPM != nil && *s.TPM > 0 {
			if toks >= float64(*s.TPM) {
				l.reject("tpm")
				return nil, rem, &LimitError{s.Label, "tpm", *s.TPM, retry}
			}
			rem.Tokens = minRem(rem.Tokens, *s.TPM-int(toks))
		}
	}
	for _, s := range subjects {
		w := l.win(s.ID)
		w.reqs++
		w.inflight++
	}
	var once sync.Once
	release = func(tokens int) {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			n := time.Now()
			for _, s := range subjects {
				w := l.win(s.ID)
				w.roll(n)
				w.inflight--
				w.toks += tokens
			}
		})
	}
	return release, rem, nil
}

func minRem(a, b int) int {
	if b < 0 {
		b = 0
	}
	if a < 0 || b < a {
		return b
	}
	return a
}

func (l *Limiter) reject(kind string) {
	if l.OnReject != nil {
		l.OnReject(kind)
	}
}

func (l *Limiter) win(id string) *window {
	w, ok := l.wins[id]
	if !ok {
		w = &window{}
		l.wins[id] = w
	}
	return w
}

// Usage reports the current approximate rpm/tpm and in-flight count for a subject.
func (l *Limiter) Usage(id string) (rpm, tpm float64, inflight int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.wins[id]
	if !ok {
		return 0, 0, 0
	}
	r, t := w.roll(time.Now())
	return r, t, w.inflight
}

// GC drops idle windows; call periodically.
func (l *Limiter) GC() {
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := time.Now().Unix()/60 - 2
	for k, w := range l.wins {
		if w.minute < cut && w.inflight == 0 {
			delete(l.wins, k)
		}
	}
}
