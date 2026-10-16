// Package spend computes request cost and persists request logs, spend counters
// and daily rollups asynchronously in batches.
package spend

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"lemongate/internal/metrics"
)

// Record is one completed (or failed) gateway request.
type Record struct {
	RequestID        string
	CreatedAt        time.Time
	Route            string
	Model            string
	ModelGroup       string
	DeploymentID     string
	APIBase          string
	KeyID            string
	KeyAlias         string
	UserID           string
	TeamID           string
	OrgID            string
	EndUser          string
	Tags             []string
	Status           string // success | error | blocked
	HTTPStatus       int
	PromptTokens     int
	CompletionTokens int
	Cost             float64
	LatencyMs        int
	TTFTMs           *int
	Stream           bool
	CacheHit         bool
	Attempts         int
	Error            string
	RequestBody      []byte // JSON, nil when payload storage is off
	ResponseBody     []byte
	Metadata         map[string]any
}

// Cost computes the USD cost of a call from per-million-token prices.
func Cost(promptTokens, completionTokens int, inputPerM, outputPerM float64) float64 {
	return float64(promptTokens)*inputPerM/1e6 + float64(completionTokens)*outputPerM/1e6
}

type Writer struct {
	pool *pgxpool.Pool
	ch   chan Record

	mu      sync.Mutex
	pending map[string]float64 // entity → unflushed spend

	observers  []func(Record)
	afterFlush []func()
}

func NewWriter(pool *pgxpool.Pool) *Writer {
	return &Writer{pool: pool, ch: make(chan Record, 10000), pending: map[string]float64{}}
}

// Observe registers a callback run (synchronously, keep it cheap) for every record.
func (w *Writer) Observe(fn func(Record)) { w.observers = append(w.observers, fn) }

// AfterFlush registers a callback run after each successful flush.
func (w *Writer) AfterFlush(fn func()) { w.afterFlush = append(w.afterFlush, fn) }

func (w *Writer) Submit(r Record) {
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now()
	}
	if r.Cost > 0 {
		w.mu.Lock()
		for _, e := range entities(r) {
			w.pending[e] += r.Cost
		}
		w.mu.Unlock()
	}
	for _, fn := range w.observers {
		fn(r)
	}
	select {
	case w.ch <- r:
	default:
		metrics.SpendDropped.Inc()
		slog.Warn("spend writer queue full; dropping log record", "request_id", r.RequestID)
	}
}

// QueueDepth returns the number of records waiting to be written.
func (w *Writer) QueueDepth() int { return len(w.ch) }

// Pending returns spend recorded in memory but not yet flushed for an entity
// ("key:<id>", "user:<id>", "team:<id>", "org:<id>", "end_user:<id>", "tag:<name>").
func (w *Writer) Pending(entity string) float64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.pending[entity]
}

func entities(r Record) []string {
	var out []string
	add := func(prefix, id string) {
		if id != "" {
			out = append(out, prefix+id)
		}
	}
	add("key:", r.KeyID)
	add("user:", r.UserID)
	add("team:", r.TeamID)
	add("org:", r.OrgID)
	add("end_user:", r.EndUser)
	if r.TeamID != "" && r.UserID != "" {
		out = append(out, "member:"+r.TeamID+":"+r.UserID)
	}
	for _, t := range r.Tags {
		add("tag:", t)
	}
	return out
}

func (w *Writer) Run(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var batch []Record
	flush := func() {
		if len(batch) == 0 {
			return
		}
		fctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := w.flush(fctx, batch); err != nil {
			slog.Error("spend flush failed", "err", err, "records", len(batch))
		}
		cancel()
		w.mu.Lock()
		for _, r := range batch {
			if r.Cost > 0 {
				for _, e := range entities(r) {
					w.pending[e] -= r.Cost
					if w.pending[e] < 1e-12 {
						delete(w.pending, e)
					}
				}
			}
		}
		w.mu.Unlock()
		for _, fn := range w.afterFlush {
			fn()
		}
		batch = batch[:0]
	}
	for {
		select {
		case r := <-w.ch:
			batch = append(batch, r)
			if len(batch) >= 500 {
				flush()
			}
		case <-tick.C:
			flush()
		case <-ctx.Done():
			for {
				select {
				case r := <-w.ch:
					batch = append(batch, r)
				default:
					flush()
					return
				}
			}
		}
	}
}

func nullUUID(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullJSON(b []byte) any {
	if len(b) == 0 || !json.Valid(b) {
		return nil
	}
	return json.RawMessage(b)
}

type dayKey struct{ day, key, user, team, org, endUser, model string }
type tagKey struct{ day, tag, model string }
type agg struct {
	reqs, fails, hits, pt, ct, lat int64
	cost                           float64
}

func (w *Writer) flush(ctx context.Context, recs []Record) error {
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	rows := make([][]any, 0, len(recs))
	for _, r := range recs {
		meta := r.Metadata
		if meta == nil {
			meta = map[string]any{}
		}
		tags := r.Tags
		if tags == nil {
			tags = []string{}
		}
		rows = append(rows, []any{r.RequestID, r.CreatedAt, r.Route, r.Model, r.ModelGroup, nullUUID(r.DeploymentID), r.APIBase,
			nullUUID(r.KeyID), r.KeyAlias, nullUUID(r.UserID), nullUUID(r.TeamID), nullUUID(r.OrgID), r.EndUser, tags, r.Status,
			r.HTTPStatus, r.PromptTokens, r.CompletionTokens, r.PromptTokens + r.CompletionTokens, r.Cost, r.LatencyMs, r.TTFTMs,
			r.Stream, r.CacheHit, max(r.Attempts, 1), r.Error, nullJSON(r.RequestBody), nullJSON(r.ResponseBody), meta})
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"request_logs"}, []string{"request_id", "created_at", "route", "model",
		"model_group", "deployment_id", "api_base", "key_id", "key_alias", "user_id", "team_id", "org_id", "end_user", "tags",
		"status", "http_status", "prompt_tokens", "completion_tokens", "total_tokens", "cost", "latency_ms", "ttft_ms", "stream",
		"cache_hit", "attempts", "error", "request_body", "response_body", "metadata"}, pgx.CopyFromRows(rows)); err != nil {
		return err
	}

	days := map[dayKey]*agg{}
	tagDays := map[tagKey]*agg{}
	spendBy := map[string]map[string]float64{"api_keys": {}, "users": {}, "teams": {}, "organizations": {}}
	endUsers := map[string]float64{}
	tagSpend := map[string]float64{}
	memberSpend := map[[2]string]float64{}
	for _, r := range recs {
		day := r.CreatedAt.UTC().Format("2006-01-02")
		k := dayKey{day, r.KeyID, r.UserID, r.TeamID, r.OrgID, r.EndUser, r.ModelGroup}
		a := days[k]
		if a == nil {
			a = &agg{}
			days[k] = a
		}
		bump(a, r)
		for _, t := range r.Tags {
			tk := tagKey{day, t, r.ModelGroup}
			ta := tagDays[tk]
			if ta == nil {
				ta = &agg{}
				tagDays[tk] = ta
			}
			bump(ta, r)
			tagSpend[t] += r.Cost
		}
		if r.EndUser != "" {
			endUsers[r.EndUser] += r.Cost
		}
		if r.Cost == 0 {
			continue
		}
		for table, id := range map[string]string{"api_keys": r.KeyID, "users": r.UserID, "teams": r.TeamID, "organizations": r.OrgID} {
			if id != "" {
				spendBy[table][id] += r.Cost
			}
		}
		if r.TeamID != "" && r.UserID != "" {
			memberSpend[[2]string{r.TeamID, r.UserID}] += r.Cost
		}
	}

	b := &pgx.Batch{}
	for k, a := range days {
		b.Queue(`INSERT INTO daily_spend (day, key_id, user_id, team_id, org_id, end_user, model, requests, failures, cache_hits,
			prompt_tokens, completion_tokens, cost, latency_ms_sum) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
			ON CONFLICT (day, key_id, user_id, team_id, org_id, end_user, model) DO UPDATE SET
			requests = daily_spend.requests + EXCLUDED.requests, failures = daily_spend.failures + EXCLUDED.failures,
			cache_hits = daily_spend.cache_hits + EXCLUDED.cache_hits, prompt_tokens = daily_spend.prompt_tokens + EXCLUDED.prompt_tokens,
			completion_tokens = daily_spend.completion_tokens + EXCLUDED.completion_tokens, cost = daily_spend.cost + EXCLUDED.cost,
			latency_ms_sum = daily_spend.latency_ms_sum + EXCLUDED.latency_ms_sum`,
			k.day, k.key, k.user, k.team, k.org, k.endUser, k.model, a.reqs, a.fails, a.hits, a.pt, a.ct, a.cost, a.lat)
	}
	for k, a := range tagDays {
		b.Queue(`INSERT INTO daily_tag_spend (day, tag, model, requests, failures, prompt_tokens, completion_tokens, cost)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (day, tag, model) DO UPDATE SET
			requests = daily_tag_spend.requests + EXCLUDED.requests, failures = daily_tag_spend.failures + EXCLUDED.failures,
			prompt_tokens = daily_tag_spend.prompt_tokens + EXCLUDED.prompt_tokens,
			completion_tokens = daily_tag_spend.completion_tokens + EXCLUDED.completion_tokens, cost = daily_tag_spend.cost + EXCLUDED.cost`,
			k.day, k.tag, k.model, a.reqs, a.fails, a.pt, a.ct, a.cost)
	}
	for table, m := range spendBy {
		for id, c := range m {
			b.Queue(`UPDATE `+table+` SET spend = spend + $2 WHERE id = $1`, id, c)
		}
	}
	for k, c := range memberSpend {
		b.Queue(`UPDATE team_members SET spend = spend + $3 WHERE team_id = $1 AND user_id = $2`, k[0], k[1], c)
	}
	for id, c := range endUsers {
		b.Queue(`INSERT INTO end_users (id, spend) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET spend = end_users.spend + $2, last_seen_at = now()`, id, c)
	}
	for t, c := range tagSpend {
		if c > 0 {
			b.Queue(`UPDATE tags SET spend = spend + $2 WHERE name = $1`, t, c)
		}
	}
	keyIDs := map[string]bool{}
	for _, r := range recs {
		if r.KeyID != "" {
			keyIDs[r.KeyID] = true
		}
	}
	if len(keyIDs) > 0 {
		ids := make([]string, 0, len(keyIDs))
		for id := range keyIDs {
			ids = append(ids, id)
		}
		b.Queue(`UPDATE api_keys SET last_used_at = now() WHERE id = ANY($1::uuid[])`, ids)
	}
	if err := tx.SendBatch(ctx, b).Close(); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func bump(a *agg, r Record) {
	a.reqs++
	if r.Status != "success" {
		a.fails++
	}
	if r.CacheHit {
		a.hits++
	}
	a.pt += int64(r.PromptTokens)
	a.ct += int64(r.CompletionTokens)
	a.cost += r.Cost
	a.lat += int64(r.LatencyMs)
}
