package analytics

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// LogFilter scopes a request_logs query. Empty fields are unconstrained.
type LogFilter struct {
	Since, Until time.Time // optional time window on created_at
	Status       string    // success | error | blocked | cached | failed (error+blocked)
	Model        string    // model group
	KeyID        string
	TeamID       string
	UserID       string
	OrgID        string
	EndUser      string
	Search       string // request id / error text / key alias
	// Member scoping, same semantics as Filter.
	KeyIDs      []string
	TeamIDs     []string
	ScopeUserID string
	// Keyset cursor: rows strictly older than (BeforeAt, BeforeID).
	BeforeAt time.Time
	BeforeID string
	Limit    int
}

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// IsUUID reports whether s looks like a UUID.
func IsUUID(s string) bool { return uuidRe.MatchString(s) }

func (f LogFilter) scoped() bool { return f.KeyIDs != nil || f.TeamIDs != nil || f.ScopeUserID != "" }

func onlyUUIDs(in []string) []string {
	out := []string{}
	for _, s := range in {
		if IsUUID(s) {
			out = append(out, s)
		}
	}
	return out
}

func (f LogFilter) where(args *[]any) string {
	add := func(v any) string {
		*args = append(*args, v)
		return fmt.Sprintf("$%d", len(*args))
	}
	conds := []string{"true"}
	if !f.Since.IsZero() {
		conds = append(conds, "l.created_at >= "+add(f.Since))
	}
	if !f.Until.IsZero() {
		conds = append(conds, "l.created_at < "+add(f.Until))
	}
	switch f.Status {
	case "success", "error", "blocked":
		conds = append(conds, "l.status = "+add(f.Status))
	case "failed":
		conds = append(conds, "l.status <> 'success'")
	case "cached":
		conds = append(conds, "l.cache_hit")
	}
	if f.Model != "" {
		conds = append(conds, "(l.model_group = "+add(f.Model)+" OR l.model = "+add(f.Model)+")")
	}
	for col, v := range map[string]string{"key_id": f.KeyID, "team_id": f.TeamID, "user_id": f.UserID, "org_id": f.OrgID} {
		if v == "" {
			continue
		}
		if !IsUUID(v) {
			conds = append(conds, "false")
			continue
		}
		conds = append(conds, "l."+col+" = "+add(v)+"::uuid")
	}
	if f.EndUser != "" {
		conds = append(conds, "l.end_user = "+add(f.EndUser))
	}
	if s := strings.TrimSpace(f.Search); s != "" {
		p := add("%" + s + "%")
		conds = append(conds, "(l.request_id ILIKE "+p+" OR l.error ILIKE "+p+" OR l.key_alias ILIKE "+p+" OR l.end_user ILIKE "+p+")")
	}
	if f.scoped() {
		cond := "l.key_id = ANY(" + add(onlyUUIDs(f.KeyIDs)) + "::uuid[]) OR l.team_id = ANY(" + add(onlyUUIDs(f.TeamIDs)) + "::uuid[])"
		if IsUUID(f.ScopeUserID) {
			cond += " OR l.user_id = " + add(f.ScopeUserID) + "::uuid"
		}
		conds = append(conds, "("+cond+")")
	}
	if !f.BeforeAt.IsZero() && IsUUID(f.BeforeID) {
		conds = append(conds, "(l.created_at, l.id) < ("+add(f.BeforeAt)+", "+add(f.BeforeID)+"::uuid)")
	}
	return strings.Join(conds, " AND ")
}

// logFilterFrom converts a daily filter into an equivalent log filter.
func logFilterFrom(f Filter) LogFilter {
	return LogFilter{Since: truncDay(f.From), Until: truncDay(f.To).AddDate(0, 0, 1), Model: f.Model, KeyID: f.KeyID,
		TeamID: f.TeamID, UserID: f.UserID, OrgID: f.OrgID, EndUser: f.EndUser, KeyIDs: f.KeyIDs, TeamIDs: f.TeamIDs, ScopeUserID: f.ScopeUserID}
}

// LogsFor converts a usage filter into a log filter covering the same days and scope.
func LogsFor(f Filter) LogFilter { return logFilterFrom(f) }

// LogEntry is one request_logs row joined with owner labels.
type LogEntry struct {
	ID               string         `db:"id"`
	RequestID        string         `db:"request_id"`
	CreatedAt        time.Time      `db:"created_at"`
	Route            string         `db:"route"`
	Model            string         `db:"model"`
	ModelGroup       string         `db:"model_group"`
	DeploymentID     *string        `db:"deployment_id"`
	APIBase          string         `db:"api_base"`
	KeyID            *string        `db:"key_id"`
	KeyAlias         string         `db:"key_alias"`
	UserID           *string        `db:"user_id"`
	TeamID           *string        `db:"team_id"`
	OrgID            *string        `db:"org_id"`
	EndUser          string         `db:"end_user"`
	Tags             []string       `db:"tags"`
	Status           string         `db:"status"`
	HTTPStatus       int            `db:"http_status"`
	PromptTokens     int            `db:"prompt_tokens"`
	CompletionTokens int            `db:"completion_tokens"`
	TotalTokens      int            `db:"total_tokens"`
	Cost             float64        `db:"cost"`
	LatencyMs        int            `db:"latency_ms"`
	TTFTMs           *int           `db:"ttft_ms"`
	Stream           bool           `db:"stream"`
	CacheHit         bool           `db:"cache_hit"`
	Attempts         int            `db:"attempts"`
	Error            string         `db:"error"`
	RequestBody      []byte         `db:"request_body"`
	ResponseBody     []byte         `db:"response_body"`
	Metadata         map[string]any `db:"metadata"`
	UserEmail        *string        `db:"user_email"`
	TeamName         *string        `db:"team_name"`
	KeyHint          *string        `db:"key_hint"`
}

// HasPayload reports whether request or response bodies were stored.
func (e LogEntry) HasPayload() bool { return len(e.RequestBody) > 0 || len(e.ResponseBody) > 0 }

// Cursor encodes the keyset position after this row.
func (e LogEntry) Cursor() string {
	return e.CreatedAt.UTC().Format(time.RFC3339Nano) + "_" + e.ID
}

// ParseCursor decodes a cursor produced by LogEntry.Cursor.
func ParseCursor(s string) (time.Time, string, bool) {
	at, id, ok := strings.Cut(s, "_")
	if !ok || !IsUUID(id) {
		return time.Time{}, "", false
	}
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return time.Time{}, "", false
	}
	return t, id, true
}

const logListCols = `l.id::text AS id, l.request_id, l.created_at, l.route, l.model, l.model_group, l.deployment_id::text AS deployment_id,
	l.api_base, l.key_id::text AS key_id, l.key_alias, l.user_id::text AS user_id, l.team_id::text AS team_id, l.org_id::text AS org_id,
	l.end_user, l.tags, l.status, l.http_status, l.prompt_tokens, l.completion_tokens, l.total_tokens, l.cost, l.latency_ms, l.ttft_ms,
	l.stream, l.cache_hit, l.attempts, l.error, l.metadata, u.email AS user_email, t.name AS team_name, k.key_hint AS key_hint`

const logJoins = ` FROM request_logs l LEFT JOIN users u ON u.id = l.user_id LEFT JOIN teams t ON t.id = l.team_id LEFT JOIN api_keys k ON k.id = l.key_id`

// ListLogs returns up to f.Limit rows (newest first) without payload bodies.
func ListLogs(ctx context.Context, pool *pgxpool.Pool, f LogFilter) ([]LogEntry, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}
	var args []any
	where := f.where(&args)
	args = append(args, f.Limit)
	rows, err := pool.Query(ctx, `SELECT `+logListCols+logJoins+` WHERE `+where+` ORDER BY l.created_at DESC, l.id DESC LIMIT $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByNameLax[LogEntry])
}

// GetLog loads one log row including payloads. Scope restrictions in f apply.
func GetLog(ctx context.Context, pool *pgxpool.Pool, id string, f LogFilter) (LogEntry, error) {
	if !IsUUID(id) {
		return LogEntry{}, pgx.ErrNoRows
	}
	f.BeforeAt, f.BeforeID, f.Since, f.Until = time.Time{}, "", time.Time{}, time.Time{}
	args := []any{id}
	where := f.where(&args)
	rows, err := pool.Query(ctx, `SELECT `+logListCols+`, l.request_body, l.response_body`+logJoins+` WHERE l.id = $1::uuid AND `+where, args...)
	if err != nil {
		return LogEntry{}, err
	}
	return pgx.CollectExactlyOneRow(rows, pgx.RowToStructByNameLax[LogEntry])
}

// LogStats summarizes a log window (used for the logs page header).
type LogStats struct {
	Requests     int64
	Failures     int64
	CacheHits    int64
	Cost         float64
	AvgLatencyMs float64
	P95LatencyMs float64
	AvgTTFTMs    float64
}

func (s LogStats) ErrorRate() float64 {
	if s.Requests == 0 {
		return 0
	}
	return float64(s.Failures) / float64(s.Requests) * 100
}

// GetLogStats aggregates the filtered logs (cursor ignored).
func GetLogStats(ctx context.Context, pool *pgxpool.Pool, f LogFilter) (LogStats, error) {
	f.BeforeAt, f.BeforeID = time.Time{}, ""
	var args []any
	var s LogStats
	err := pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE l.status <> 'success'), count(*) FILTER (WHERE l.cache_hit),
		COALESCE(sum(l.cost),0), COALESCE(avg(l.latency_ms),0)::float8,
		COALESCE(percentile_cont(0.95) WITHIN GROUP (ORDER BY l.latency_ms),0)::float8, COALESCE(avg(l.ttft_ms),0)::float8
		FROM request_logs l WHERE `+f.where(&args), args...).Scan(&s.Requests, &s.Failures, &s.CacheHits, &s.Cost, &s.AvgLatencyMs, &s.P95LatencyMs, &s.AvgTTFTMs)
	return s, err
}

// RecentModels lists distinct model groups seen in logs since t (for filter dropdowns).
func RecentModels(ctx context.Context, pool *pgxpool.Pool, since time.Time) []string {
	rows, err := pool.Query(ctx, `SELECT DISTINCT model FROM daily_spend WHERE day >= $1::date AND model <> '' ORDER BY 1`, since.Format("2006-01-02"))
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var m string
		if rows.Scan(&m) == nil {
			out = append(out, m)
		}
	}
	return out
}
