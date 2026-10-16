// Package settings holds runtime-tunable settings persisted in the `settings` table.
// Each section is a JSON document; readers get an immutable snapshot via Current().
package settings

import (
	"context"
	"encoding/json"
	"sync/atomic"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Routing struct {
	Strategy          string  `json:"strategy"` // weighted | least_busy | latency | usage
	NumRetries        int     `json:"num_retries"`
	RetryBackoffMs    int     `json:"retry_backoff_ms"`
	DefaultTimeoutSec int     `json:"default_timeout_sec"`
	CooldownFailures  int     `json:"cooldown_failures"` // failures within a minute before cooldown
	CooldownSeconds   int     `json:"cooldown_seconds"`
	HealthCheckSec    int     `json:"health_check_sec"` // 0 disables background probes
	LatencyEWMAAlpha  float64 `json:"latency_ewma_alpha"`
}

type Logging struct {
	StorePayloads   bool `json:"store_payloads"`
	RedactPayloads  bool `json:"redact_payloads"` // apply PII masking to stored payloads
	RetentionDays   int  `json:"retention_days"`
	MaxPayloadBytes int  `json:"max_payload_bytes"`
}

type Cache struct {
	Enabled    bool `json:"enabled"`
	TTLSeconds int  `json:"ttl_seconds"`
	MaxEntries int  `json:"max_entries"`
	PerKey     bool `json:"per_key"` // scope cache entries to the calling key
}

type General struct {
	DefaultKeyBudget   *float64 `json:"default_key_budget"`
	DefaultKeyDuration string   `json:"default_key_duration"` // e.g. "30d", "" = never
	AllowMemberKeys    bool     `json:"allow_member_keys"`
	MaxRequestBytes    int      `json:"max_request_bytes"`
	TrackEndUsers      bool     `json:"track_end_users"`
}

type Branding struct {
	AppName string `json:"app_name"`
	LogoURL string `json:"logo_url"`
	Tagline string `json:"tagline"`
}

type Alerting struct {
	BudgetThresholds   []int `json:"budget_thresholds"` // percent
	ErrorRatePercent   int   `json:"error_rate_percent"`
	SlowResponseSec    int   `json:"slow_response_sec"`
	DedupeMinutes      int   `json:"dedupe_minutes"`
	DailyReport        bool  `json:"daily_report"`
	DailyReportHourUTC int   `json:"daily_report_hour_utc"`
	KeyExpiryDays      int   `json:"key_expiry_days"`
}

type Metrics struct {
	Enabled       bool `json:"enabled"`        // serve /metrics
	RequireAuth   bool `json:"require_auth"`   // demand the metrics token or master key
	EntityMetrics bool `json:"entity_metrics"` // per key/team/user/org spend and budget gauges
}

type Settings struct {
	Routing  Routing  `json:"routing"`
	Logging  Logging  `json:"logging"`
	Cache    Cache    `json:"cache"`
	General  General  `json:"general"`
	Branding Branding `json:"branding"`
	Alerting Alerting `json:"alerting"`
	Metrics  Metrics  `json:"metrics"`
}

func Defaults() Settings {
	return Settings{
		Routing: Routing{Strategy: "weighted", NumRetries: 2, RetryBackoffMs: 250, DefaultTimeoutSec: 600,
			CooldownFailures: 3, CooldownSeconds: 30, HealthCheckSec: 60, LatencyEWMAAlpha: 0.3},
		Logging:  Logging{StorePayloads: false, RedactPayloads: true, RetentionDays: 30, MaxPayloadBytes: 64 << 10},
		Cache:    Cache{Enabled: false, TTLSeconds: 600, MaxEntries: 5000, PerKey: true},
		General:  General{AllowMemberKeys: true, MaxRequestBytes: 32 << 20, TrackEndUsers: true},
		Branding: Branding{AppName: "LemonGate", Tagline: "Self-hosted AI gateway"},
		Alerting: Alerting{BudgetThresholds: []int{50, 80, 100}, ErrorRatePercent: 25, SlowResponseSec: 60,
			DedupeMinutes: 60, DailyReport: false, DailyReportHourUTC: 8, KeyExpiryDays: 7},
		Metrics: Metrics{Enabled: true},
	}
}

type Store struct {
	pool *pgxpool.Pool
	cur  atomic.Pointer[Settings]
	subs []func(Settings)
}

func NewStore(pool *pgxpool.Pool) *Store {
	s := &Store{pool: pool}
	d := Defaults()
	s.cur.Store(&d)
	return s
}

func (s *Store) Current() Settings { return *s.cur.Load() }

// OnChange registers a callback invoked after every successful save.
func (s *Store) OnChange(fn func(Settings)) { s.subs = append(s.subs, fn) }

// Load merges persisted sections over defaults, then applies overrides from the
// YAML file (which win, but are not persisted).
func (s *Store) Load(ctx context.Context, fileOverrides map[string]any) error {
	merged := Defaults()
	rows, err := s.pool.Query(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return err
	}
	stored := map[string]json.RawMessage{}
	for rows.Next() {
		var k string
		var v []byte
		if err := rows.Scan(&k, &v); err != nil {
			rows.Close()
			return err
		}
		stored[k] = v
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for k, v := range fileOverrides {
		b, _ := json.Marshal(v)
		stored[k] = mergeJSON(stored[k], b)
	}
	b, _ := json.Marshal(stored)
	if err := json.Unmarshal(b, &merged); err != nil {
		return err
	}
	s.cur.Store(&merged)
	return nil
}

func mergeJSON(base, over json.RawMessage) json.RawMessage {
	m := map[string]any{}
	_ = json.Unmarshal(base, &m)
	o := map[string]any{}
	_ = json.Unmarshal(over, &o)
	for k, v := range o {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return b
}

// Update applies fn to a copy of the current settings and persists every section.
func (s *Store) Update(ctx context.Context, fn func(*Settings)) (Settings, error) {
	next := s.Current()
	fn(&next)
	sections := map[string]any{
		"routing": next.Routing, "logging": next.Logging, "cache": next.Cache,
		"general": next.General, "branding": next.Branding, "alerting": next.Alerting, "metrics": next.Metrics,
	}
	for k, v := range sections {
		b, _ := json.Marshal(v)
		if _, err := s.pool.Exec(ctx, `INSERT INTO settings(key, value, updated_at) VALUES ($1, $2, now())
			ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, k, b); err != nil {
			return next, err
		}
	}
	s.cur.Store(&next)
	for _, fn := range s.subs {
		fn(next)
	}
	return next, nil
}
