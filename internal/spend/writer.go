// Package spend computes request cost and persists request logs, spend counters
// and daily rollups asynchronously in batches.
package spend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

// maxRetained bounds the records held in memory while the database is unreachable.
const maxRetained = 20000

type Writer struct {
	pool    *pgxpool.Pool
	ch      chan Record
	flushFn func(context.Context, []Record) error // w.flush; replaced in tests

	mu      sync.Mutex
	pending map[string]float64 // entity → unflushed spend

	observers  []func(Record)
	afterFlush []func()
}

func NewWriter(pool *pgxpool.Pool) *Writer {
	w := &Writer{pool: pool, ch: make(chan Record, 10000), pending: map[string]float64{}}
	w.flushFn = w.flush
	return w
}

// Observe registers a callback run (synchronously, keep it cheap) for every record.
func (w *Writer) Observe(fn func(Record)) { w.observers = append(w.observers, fn) }

// AfterFlush registers a callback run after each successful flush.
func (w *Writer) AfterFlush(fn func()) { w.afterFlush = append(w.afterFlush, fn) }

func (w *Writer) Submit(r Record) {
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now()
	}
	// Sanitize before computing pending entities so they match what is written.
	r = sanitize(r)
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
		w.settle([]Record{r})
		metrics.SpendDropped.Inc()
		slog.Warn("spend writer queue full; dropping log record", "request_id", r.RequestID, "cost", r.Cost)
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
	failing := false // the last flush hit a transient error: only retry on the tick
	flush := func() {
		if len(batch) == 0 {
			return
		}
		settled, retry, committed := w.write(batch)
		if committed > 0 {
			// Reload cached spend before releasing pending, so budgets briefly count
			// a record twice rather than not at all.
			for _, fn := range w.afterFlush {
				fn()
			}
		}
		if over := len(retry) - maxRetained; over > 0 {
			metrics.SpendDropped.Add(float64(over))
			slog.Error("spend writer backlog full; dropping oldest records", "records", over)
			settled = append(settled, retry[:over]...)
			retry = slices.Clone(retry[over:])
		}
		w.settle(settled)
		failing = len(retry) > 0
		batch = retry
	}
	for {
		select {
		case r := <-w.ch:
			batch = append(batch, r)
			if len(batch) >= 500 && !failing {
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
					if len(batch) > 0 {
						metrics.SpendDropped.Add(float64(len(batch)))
						slog.Error("spend writer stopped with unwritten records", "records", len(batch))
					}
					return
				}
			}
		}
	}
}

// settle releases the pending spend of records that were written or given up on.
func (w *Writer) settle(recs []Record) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, r := range recs {
		if r.Cost <= 0 {
			continue
		}
		for _, e := range entities(r) {
			w.pending[e] -= r.Cost
			if w.pending[e] < 1e-12 {
				delete(w.pending, e)
			}
		}
	}
}

// write persists recs. When the database rejects the batch it is split, so a
// record that cannot be stored only takes itself down. It returns the records
// that were committed or dropped (settled), those that hit a transient error and
// should be retried, and how many were committed.
func (w *Writer) write(recs []Record) (settled, retry []Record, committed int) {
	err := w.tryFlush(recs)
	switch {
	case err == nil:
		return recs, nil, len(recs)
	case transient(err):
		slog.Warn("spend flush failed; will retry", "err", err, "records", len(recs))
		return nil, recs, 0
	case len(recs) > 1:
		slog.Warn("spend flush rejected; retrying in smaller batches", "err", err, "records", len(recs))
		mid := len(recs) / 2
		s1, r1, c1 := w.write(recs[:mid])
		s2, r2, c2 := w.write(recs[mid:])
		return slices.Concat(s1, s2), slices.Concat(r1, r2), c1 + c2
	}
	// A single record the database refuses: keep its accounting and drop the
	// free-form parts (payloads, metadata) that most likely caused it.
	r := recs[0]
	slim := r
	slim.RequestBody, slim.ResponseBody = nil, nil
	slim.Metadata = map[string]any{"payloads_dropped": true}
	err2 := w.tryFlush([]Record{slim})
	switch {
	case err2 == nil:
		slog.Warn("spend record stored without payloads or metadata after the database rejected it",
			"request_id", r.RequestID, "err", err)
		return recs, nil, 1
	case transient(err2):
		return nil, recs, 0
	}
	metrics.SpendDropped.Inc()
	slog.Error("dropping spend record rejected by the database", "request_id", r.RequestID, "cost", r.Cost, "err", err2)
	return recs, nil, 0
}

func (w *Writer) tryFlush(recs []Record) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return w.flushFn(ctx, recs)
}

// transient reports failures where the database could not be reached or asked
// for a retry, as opposed to rejecting the data.
func transient(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code[:min(len(pgErr.Code), 2)] {
		case "08", "40", "53", "57": // connection, rollback (deadlock), resources, operator intervention
			return true
		}
		return false
	}
	var connErr *pgconn.ConnectError
	var netErr net.Error
	return errors.As(err, &connErr) || errors.As(err, &netErr) || pgconn.Timeout(err) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
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

// Bounds for client-supplied attribution. Tags and end users are part of the
// rollup tables' primary keys, so they must stay well under the index row limit.
const (
	MaxTags         = 32
	MaxTagLen       = 128
	MaxEndUserLen   = 256
	MaxMetadataSize = 16 << 10 // bytes of JSON
)

// CleanText makes s storable in a Postgres text column, which rejects NUL bytes
// and invalid UTF-8.
func CleanText(s string) string {
	if strings.IndexByte(s, 0) < 0 && utf8.ValidString(s) {
		return s
	}
	return strings.ReplaceAll(strings.ToValidUTF8(s, "\uFFFD"), "\x00", "")
}

// truncate cuts s to at most n bytes without splitting a UTF-8 sequence.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// CleanEndUser bounds a client-supplied end-user id.
func CleanEndUser(s string) string { return truncate(CleanText(s), MaxEndUserLen) }

// CleanTags makes tags storable, drops empties and duplicates, and keeps at most
// MaxTags of them (earlier tags win).
func CleanTags(tags []string) []string {
	if tags == nil {
		return nil
	}
	out := make([]string, 0, min(len(tags), MaxTags))
	for _, t := range tags {
		t = strings.TrimSpace(truncate(strings.TrimSpace(CleanText(t)), MaxTagLen))
		if t == "" || slices.Contains(out, t) {
			continue
		}
		if len(out) == MaxTags {
			break
		}
		out = append(out, t)
	}
	return out
}

// CleanMetadata strips NULs from keys and values (recursively) and replaces
// metadata whose JSON encoding exceeds MaxMetadataSize with a small marker.
func CleanMetadata(md map[string]any) map[string]any {
	out, _ := cleanValue(md).(map[string]any)
	b, err := json.Marshal(out)
	if err != nil || len(b) > MaxMetadataSize {
		return map[string]any{"truncated": true, "bytes": len(b)}
	}
	return out
}

// cleanValue returns a copy of a decoded JSON value that Postgres accepts as jsonb:
// no NULs in strings or keys, valid UTF-8, and numbers within numeric's range.
func cleanValue(v any) any {
	switch t := v.(type) {
	case string:
		return CleanText(t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[CleanText(k)] = cleanValue(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = cleanValue(x)
		}
		return out
	case []string:
		out := make([]string, len(t))
		for i, x := range t {
			out[i] = CleanText(x)
		}
		return out
	case json.Number:
		// Literals like 1e999999 decode fine but overflow Postgres numeric.
		if len(t) <= 32 && !strings.ContainsAny(string(t), "eE") {
			return t
		}
		f, err := t.Float64()
		if err != nil || math.IsInf(f, 0) {
			return string(t)
		}
		return json.Number(strconv.FormatFloat(f, 'g', -1, 64))
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) {
			return nil
		}
	}
	return v
}

// cleanJSON returns b, re-encoded without what Postgres refuses in jsonb when it
// contains any. Invalid JSON yields nil.
func cleanJSON(b []byte) []byte {
	if len(b) == 0 || !jsonNeedsClean(b) {
		return b
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if enc.Encode(cleanValue(v)) != nil {
		return nil
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

// jsonNeedsClean reports whether b holds a \u0000 escape, an escaped UTF-16
// surrogate (Postgres rejects unpaired ones), a raw NUL or invalid UTF-8.
func jsonNeedsClean(b []byte) bool {
	if bytes.IndexByte(b, 0) >= 0 || !utf8.Valid(b) {
		return true
	}
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' {
			continue
		}
		i++ // the escaped character, so an escaped backslash followed by "u0000" is not matched
		if i+4 < len(b) && b[i] == 'u' {
			if c, err := strconv.ParseUint(string(b[i+1:i+5]), 16, 16); err == nil && (c == 0 || c >= 0xD800 && c <= 0xDFFF) {
				return true
			}
		}
	}
	return false
}

// sanitize returns r with every text and JSON field made storable.
func sanitize(r Record) Record {
	for _, f := range []*string{&r.RequestID, &r.Route, &r.Model, &r.ModelGroup, &r.APIBase, &r.KeyAlias, &r.Status, &r.Error} {
		*f = CleanText(*f)
	}
	r.EndUser = CleanEndUser(r.EndUser)
	r.Tags = CleanTags(r.Tags)
	if r.Metadata != nil {
		r.Metadata, _ = cleanValue(r.Metadata).(map[string]any)
	}
	r.RequestBody = cleanJSON(r.RequestBody)
	r.ResponseBody = cleanJSON(r.ResponseBody)
	return r
}
