package metrics

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"lemongate/internal/settings"
)

// tokenRow is the settings row holding the SHA-256 of the scrape token. It is kept
// out of the settings document because viewers can read that document.
const tokenRow = "metrics_token"

// TokenPrefix marks scrape tokens so they are recognisable in config files.
const TokenPrefix = "lgm-"

// Endpoint serves /metrics, optionally behind a bearer token.
//
// When auth is required (Settings → Metrics, or LEMONGATE_METRICS_TOKEN is set) a
// scrape must present the generated scrape token, the environment token or the
// master key, as a bearer token or as the basic-auth password.
type Endpoint struct {
	Pool      *pgxpool.Pool
	Settings  *settings.Store
	MasterKey string
	EnvToken  string

	handler  http.Handler
	hash     atomic.Pointer[[32]byte] // nil when no token has been generated
	mu       sync.Mutex
	lastLoad time.Time
}

func NewEndpoint(pool *pgxpool.Pool, st *settings.Store, masterKey, envToken string) *Endpoint {
	return &Endpoint{Pool: pool, Settings: st, MasterKey: masterKey, EnvToken: envToken,
		handler: promhttp.HandlerFor(Registry, promhttp.HandlerOpts{})}
}

type tokenDoc struct {
	SHA256  string    `json:"sha256"`
	Created time.Time `json:"created"`
}

// Load reads the stored token hash.
func (e *Endpoint) Load(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.load(ctx)
}

func (e *Endpoint) load(ctx context.Context) error {
	e.lastLoad = time.Now()
	var raw []byte
	err := e.Pool.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, tokenRow).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		e.hash.Store(nil)
		return nil
	}
	if err != nil {
		return err
	}
	var d tokenDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		return err
	}
	b, err := hex.DecodeString(d.SHA256)
	if err != nil || len(b) != 32 {
		e.hash.Store(nil)
		return nil
	}
	var h [32]byte
	copy(h[:], b)
	e.hash.Store(&h)
	return nil
}

// TokenCreated returns when the current scrape token was generated (zero if none).
func (e *Endpoint) TokenCreated(ctx context.Context) time.Time {
	var raw []byte
	if e.Pool.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, tokenRow).Scan(&raw) != nil {
		return time.Time{}
	}
	var d tokenDoc
	_ = json.Unmarshal(raw, &d)
	return d.Created
}

// Rotate generates a new scrape token, replacing any previous one, and returns it.
// Only its hash is stored.
func (e *Endpoint) Rotate(ctx context.Context) (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := TokenPrefix + hex.EncodeToString(buf)
	sum := sha256.Sum256([]byte(token))
	doc, _ := json.Marshal(tokenDoc{SHA256: hex.EncodeToString(sum[:]), Created: time.Now().UTC()})
	if _, err := e.Pool.Exec(ctx, `INSERT INTO settings(key, value, updated_at) VALUES ($1, $2, now())
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, tokenRow, doc); err != nil {
		return "", err
	}
	e.hash.Store(&sum)
	return token, nil
}

// Revoke deletes the scrape token.
func (e *Endpoint) Revoke(ctx context.Context) error {
	if _, err := e.Pool.Exec(ctx, `DELETE FROM settings WHERE key = $1`, tokenRow); err != nil {
		return err
	}
	e.hash.Store(nil)
	return nil
}

// HasToken reports whether a scrape token has been generated.
func (e *Endpoint) HasToken() bool { return e.hash.Load() != nil }

// AuthRequired reports whether scrapes must authenticate.
func (e *Endpoint) AuthRequired() bool {
	return e.EnvToken != "" || e.Settings.Current().Metrics.RequireAuth
}

func (e *Endpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !e.Settings.Current().Metrics.Enabled {
		http.NotFound(w, r)
		return
	}
	if e.AuthRequired() && !e.authorized(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
		http.Error(w, "metrics require a scrape token", http.StatusUnauthorized)
		return
	}
	e.handler.ServeHTTP(w, r)
}

func (e *Endpoint) authorized(r *http.Request) bool {
	tok := ""
	if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		tok = strings.TrimSpace(h[7:])
	} else if _, pw, ok := r.BasicAuth(); ok {
		tok = pw
	}
	if tok == "" {
		return false
	}
	if eq(tok, e.MasterKey) || eq(tok, e.EnvToken) {
		return true
	}
	if !strings.HasPrefix(tok, TokenPrefix) {
		return false
	}
	sum := sha256.Sum256([]byte(tok))
	if h := e.hash.Load(); h != nil && subtle.ConstantTimeCompare(h[:], sum[:]) == 1 {
		return true
	}
	// The token may have been rotated through another replica: re-read, at most every 30s.
	e.mu.Lock()
	stale := time.Since(e.lastLoad) > 30*time.Second
	if stale {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		_ = e.load(ctx)
		cancel()
	}
	e.mu.Unlock()
	h := e.hash.Load()
	return stale && h != nil && subtle.ConstantTimeCompare(h[:], sum[:]) == 1
}

func eq(a, b string) bool {
	return b != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
