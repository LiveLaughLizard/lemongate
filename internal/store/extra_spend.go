package store

import (
	"context"
	"fmt"
	"net/url"
	"time"
)

// Queries backing the end users, tags and budgets console areas.

// --- end users ---

// UpdateEndUser saves editable fields without touching spend. The budget reset
// time is only recomputed when the period changes.
func (s *Store) UpdateEndUser(ctx context.Context, e EndUser) error {
	return exec(ctx, s, `UPDATE end_users SET alias=$2, max_budget=$3,
		budget_reset_at = CASE WHEN budget_period IS DISTINCT FROM $4 THEN $5 ELSE budget_reset_at END,
		budget_period=$4, blocked=$6 WHERE id=$1`,
		e.ID, e.Alias, e.MaxBudget, e.BudgetPeriod, NextReset(e.BudgetPeriod, time.Now()), e.Blocked)
}

// CreateEndUser registers an end user ahead of traffic (fails if it exists).
func (s *Store) CreateEndUser(ctx context.Context, e EndUser) error {
	return exec(ctx, s, `INSERT INTO end_users (id, alias, max_budget, budget_period, budget_reset_at, blocked) VALUES ($1,$2,$3,$4,$5,$6)`,
		e.ID, e.Alias, e.MaxBudget, e.BudgetPeriod, NextReset(e.BudgetPeriod, time.Now()), e.Blocked)
}

func (s *Store) SetEndUserBlocked(ctx context.Context, id string, blocked bool) error {
	return exec(ctx, s, `UPDATE end_users SET blocked=$2 WHERE id=$1`, id, blocked)
}

func (s *Store) ResetEndUserSpend(ctx context.Context, id string) error {
	return exec(ctx, s, `UPDATE end_users SET spend=0 WHERE id=$1`, id)
}

type EndUserFilter struct {
	Search string
	Status string // "" | blocked | budget | over
	Sort   string // recent | spend | name
}

func (s *Store) FilterEndUsers(ctx context.Context, f EndUserFilter) ([]EndUser, error) {
	order := "last_seen_at DESC"
	switch f.Sort {
	case "spend":
		order = "spend DESC, last_seen_at DESC"
	case "name":
		order = "COALESCE(NULLIF(alias,''), id)"
	}
	return queryAll[EndUser](ctx, s, `SELECT id, alias, max_budget, budget_period, budget_reset_at, spend, blocked, first_seen_at, last_seen_at
		FROM end_users WHERE ($1 = '' OR id ILIKE '%'||$1||'%' OR alias ILIKE '%'||$1||'%')
		AND ($2 = '' OR ($2 = 'blocked' AND blocked) OR ($2 = 'budget' AND max_budget IS NOT NULL)
		     OR ($2 = 'over' AND max_budget IS NOT NULL AND spend >= max_budget))
		ORDER BY `+order+` LIMIT 1000`, f.Search, f.Status)
}

type EndUserStats struct {
	Total      int     `db:"total"`
	Active24h  int     `db:"active_24h"`
	Blocked    int     `db:"blocked"`
	WithBudget int     `db:"with_budget"`
	Spend      float64 `db:"spend"`
}

func (s *Store) GetEndUserStats(ctx context.Context) (EndUserStats, error) {
	return queryOne[EndUserStats](ctx, s, `SELECT count(*)::int AS total,
		count(*) FILTER (WHERE last_seen_at > now() - interval '24 hours')::int AS active_24h,
		count(*) FILTER (WHERE blocked)::int AS blocked,
		count(*) FILTER (WHERE max_budget IS NOT NULL)::int AS with_budget,
		COALESCE(sum(spend),0) AS spend FROM end_users`)
}

// --- tags ---

// CreateTag inserts a new tag (ErrConflict if the name exists).
func (s *Store) CreateTag(ctx context.Context, t Tag) error {
	return exec(ctx, s, `INSERT INTO tags (name, description, color, max_budget, budget_period, budget_reset_at) VALUES ($1,$2,$3,$4,$5,$6)`,
		t.Name, t.Description, t.Color, t.MaxBudget, t.BudgetPeriod, NextReset(t.BudgetPeriod, time.Now()))
}

// UpdateTag saves editable fields; the reset time only changes with the period.
func (s *Store) UpdateTag(ctx context.Context, t Tag) error {
	return exec(ctx, s, `UPDATE tags SET description=$2, color=$3, max_budget=$4,
		budget_reset_at = CASE WHEN budget_period IS DISTINCT FROM $5 THEN $6 ELSE budget_reset_at END,
		budget_period=$5 WHERE name=$1`,
		t.Name, t.Description, t.Color, t.MaxBudget, t.BudgetPeriod, NextReset(t.BudgetPeriod, time.Now()))
}

func (s *Store) ResetTagSpend(ctx context.Context, name string) error {
	return exec(ctx, s, `UPDATE tags SET spend=0 WHERE name=$1`, name)
}

// TagUsage aggregates daily_tag_spend for one tag over a window.
type TagUsage struct {
	Tag              string  `db:"tag"`
	Requests         int64   `db:"requests"`
	Failures         int64   `db:"failures"`
	PromptTokens     int64   `db:"prompt_tokens"`
	CompletionTokens int64   `db:"completion_tokens"`
	Cost             float64 `db:"cost"`
}

func (t TagUsage) Tokens() int64 { return t.PromptTokens + t.CompletionTokens }

// TagUsageSummary returns per-tag totals between from and to (inclusive days), by cost.
func (s *Store) TagUsageSummary(ctx context.Context, from, to time.Time) ([]TagUsage, error) {
	return queryAll[TagUsage](ctx, s, `SELECT tag, sum(requests)::bigint AS requests, sum(failures)::bigint AS failures,
		sum(prompt_tokens)::bigint AS prompt_tokens, sum(completion_tokens)::bigint AS completion_tokens, sum(cost) AS cost
		FROM daily_tag_spend WHERE day BETWEEN $1::date AND $2::date GROUP BY tag ORDER BY sum(cost) DESC, sum(requests) DESC`,
		from.Format("2006-01-02"), to.Format("2006-01-02"))
}

// TagModelUsage returns per-model totals for one tag (Tag holds the model name).
func (s *Store) TagModelUsage(ctx context.Context, tag string, from, to time.Time) ([]TagUsage, error) {
	return queryAll[TagUsage](ctx, s, `SELECT model AS tag, sum(requests)::bigint AS requests, sum(failures)::bigint AS failures,
		sum(prompt_tokens)::bigint AS prompt_tokens, sum(completion_tokens)::bigint AS completion_tokens, sum(cost) AS cost
		FROM daily_tag_spend WHERE tag = $1 AND day BETWEEN $2::date AND $3::date GROUP BY model ORDER BY sum(cost) DESC`,
		tag, from.Format("2006-01-02"), to.Format("2006-01-02"))
}

type TagDay struct {
	Day      time.Time `db:"day"`
	Tag      string    `db:"tag"`
	Requests int64     `db:"requests"`
	Cost     float64   `db:"cost"`
}

// TagDaily returns per-day, per-tag totals. tag "" means every tag.
func (s *Store) TagDaily(ctx context.Context, tag string, from, to time.Time) ([]TagDay, error) {
	return queryAll[TagDay](ctx, s, `SELECT day, tag, sum(requests)::bigint AS requests, sum(cost) AS cost FROM daily_tag_spend
		WHERE ($1 = '' OR tag = $1) AND day BETWEEN $2::date AND $3::date GROUP BY day, tag ORDER BY day`,
		tag, from.Format("2006-01-02"), to.Format("2006-01-02"))
}

// UnregisteredTags lists tags seen on keys or in traffic that have no tags row.
func (s *Store) UnregisteredTags(ctx context.Context) ([]string, error) {
	rows, err := s.Pool.Query(ctx, `SELECT DISTINCT t FROM (
		SELECT tag AS t FROM daily_tag_spend
		UNION SELECT unnest(tags) FROM api_keys WHERE deleted_at IS NULL) x
		WHERE t <> '' AND NOT EXISTS (SELECT 1 FROM tags g WHERE g.name = x.t) ORDER BY t LIMIT 50`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var t string
		if rows.Scan(&t) == nil {
			out = append(out, t)
		}
	}
	return out, rows.Err()
}

// TagKeyCounts maps tag name → number of active keys carrying it.
func (s *Store) TagKeyCounts(ctx context.Context) (map[string]int, error) {
	rows, err := s.Pool.Query(ctx, `SELECT t, count(*)::int FROM (SELECT unnest(tags) AS t FROM api_keys WHERE deleted_at IS NULL) x GROUP BY t`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var t string
		var n int
		if rows.Scan(&t, &n) == nil {
			out[t] = n
		}
	}
	return out, rows.Err()
}

// KeysWithTag lists active keys carrying a tag.
func (s *Store) KeysWithTag(ctx context.Context, tag string) ([]Key, error) {
	return queryAll[Key](ctx, s, `SELECT `+keyCols+keyFrom+` WHERE k.deleted_at IS NULL AND $1 = ANY(k.tags) ORDER BY k.created_at DESC LIMIT 100`, tag)
}

// --- budgets ---

// BudgetEntity is any spend-bearing entity with a budget, for the health overview.
type BudgetEntity struct {
	Kind         string     `db:"kind" json:"kind"` // key | user | team | org | tag | end_user
	ID           string     `db:"id" json:"id"`
	Name         string     `db:"name" json:"name"`
	Spend        float64    `db:"spend" json:"spend"`
	MaxBudget    *float64   `db:"max_budget" json:"max_budget"`
	BudgetPeriod string     `db:"budget_period" json:"budget_period"`
	ResetAt      *time.Time `db:"budget_reset_at" json:"budget_reset_at"`
	Blocked      bool       `db:"blocked" json:"blocked"`
}

func (b BudgetEntity) Pct() float64 {
	if b.MaxBudget == nil || *b.MaxBudget <= 0 {
		return 0
	}
	return b.Spend / *b.MaxBudget * 100
}

// Href links to the entity's console page.
func (b BudgetEntity) Href() string {
	switch b.Kind {
	case "key":
		return "/ui/keys/" + b.ID
	case "user":
		return "/ui/users/" + b.ID
	case "team":
		return "/ui/teams/" + b.ID
	case "org":
		return "/ui/orgs/" + b.ID
	case "tag":
		return "/ui/tags/" + url.PathEscape(b.ID)
	case "end_user":
		return "/ui/end-users?q=" + url.QueryEscape(b.ID)
	}
	return "#"
}

const budgetUnion = `
	SELECT 'key' AS kind, k.id::text AS id, COALESCE(NULLIF(k.alias,''), k.key_hint) AS name, k.spend, k.max_budget, k.budget_period, k.budget_reset_at, k.blocked
	  FROM api_keys k WHERE k.deleted_at IS NULL AND k.max_budget > 0
	UNION ALL SELECT 'user', u.id::text, u.email, u.spend, u.max_budget, u.budget_period, u.budget_reset_at, u.blocked FROM users u WHERE u.max_budget > 0
	UNION ALL SELECT 'team', t.id::text, t.name, t.spend, t.max_budget, t.budget_period, t.budget_reset_at, t.blocked FROM teams t WHERE t.deleted_at IS NULL AND t.max_budget > 0
	UNION ALL SELECT 'org', o.id::text, o.name, o.spend, o.max_budget, o.budget_period, o.budget_reset_at, o.blocked FROM organizations o WHERE o.max_budget > 0
	UNION ALL SELECT 'tag', g.name, g.name, g.spend, g.max_budget, g.budget_period, g.budget_reset_at, false FROM tags g WHERE g.max_budget > 0
	UNION ALL SELECT 'end_user', e.id, COALESCE(NULLIF(e.alias,''), e.id), e.spend, e.max_budget, e.budget_period, e.budget_reset_at, e.blocked FROM end_users e WHERE e.max_budget > 0`

// BudgetHealth lists budgeted entities at or above minPct of their budget, fullest first.
func (s *Store) BudgetHealth(ctx context.Context, minPct float64, kind string, limit int) ([]BudgetEntity, error) {
	if limit <= 0 {
		limit = 100
	}
	return queryAll[BudgetEntity](ctx, s, `SELECT * FROM (`+budgetUnion+`) b WHERE b.spend / b.max_budget * 100 >= $1
		AND ($2 = '' OR b.kind = $2) ORDER BY b.spend / b.max_budget DESC LIMIT $3`, minPct, kind, limit)
}

// BudgetBucket counts budgeted entities per kind and utilization band.
type BudgetBucket struct {
	Kind     string  `db:"kind"`
	Total    int     `db:"total"`
	Warn     int     `db:"warn"` // 70–99%
	Over     int     `db:"over"` // ≥100%
	Spend    float64 `db:"spend"`
	Budgeted float64 `db:"budgeted"`
}

func (s *Store) BudgetBuckets(ctx context.Context) ([]BudgetBucket, error) {
	return queryAll[BudgetBucket](ctx, s, `SELECT kind, count(*)::int AS total,
		count(*) FILTER (WHERE spend / max_budget >= 0.7 AND spend < max_budget)::int AS warn,
		count(*) FILTER (WHERE spend >= max_budget)::int AS over,
		COALESCE(sum(spend),0) AS spend, COALESCE(sum(max_budget),0) AS budgeted
		FROM (`+budgetUnion+`) b GROUP BY kind`)
}

// PresetTarget is a choice in the "apply preset" picker.
type PresetTarget struct {
	ID   string `db:"id"`
	Name string `db:"name"`
}

// PresetTargets lists entities a preset can be applied to: key | user | team | org.
func (s *Store) PresetTargets(ctx context.Context, kind string) ([]PresetTarget, error) {
	var q string
	switch kind {
	case "key":
		q = `SELECT k.id::text AS id, COALESCE(NULLIF(k.alias,''), k.key_hint) || COALESCE(' · ' || u.email, '') AS name
			FROM api_keys k LEFT JOIN users u ON u.id = k.user_id WHERE k.deleted_at IS NULL ORDER BY 2 LIMIT 1000`
	case "user":
		q = `SELECT id::text AS id, email AS name FROM users ORDER BY email LIMIT 1000`
	case "team":
		q = `SELECT id::text AS id, name FROM teams WHERE deleted_at IS NULL ORDER BY name LIMIT 1000`
	case "org":
		q = `SELECT id::text AS id, name FROM organizations ORDER BY name LIMIT 1000`
	default:
		return nil, fmt.Errorf("unknown target %q", kind)
	}
	return queryAll[PresetTarget](ctx, s, q)
}

// ApplyBudgetPreset copies a preset's budget and limits onto a key, user, team or org.
// Organizations have no parallel limit, so that field is skipped for them.
func (s *Store) ApplyBudgetPreset(ctx context.Context, kind, id string, b BudgetPreset) error {
	table := map[string]string{"key": "api_keys", "user": "users", "team": "teams", "org": "organizations"}[kind]
	if table == "" {
		return fmt.Errorf("unknown target %q", kind)
	}
	reset := NextReset(b.BudgetPeriod, time.Now())
	if kind == "org" {
		return exec(ctx, s, `UPDATE organizations SET max_budget=$2, budget_period=$3,
			budget_reset_at = CASE WHEN budget_period IS DISTINCT FROM $3 THEN $4 ELSE budget_reset_at END,
			rpm_limit=$5, tpm_limit=$6, updated_at=now() WHERE id::text=$1`, id, b.MaxBudget, b.BudgetPeriod, reset, b.RPMLimit, b.TPMLimit)
	}
	return exec(ctx, s, `UPDATE `+table+` SET max_budget=$2, budget_period=$3,
		budget_reset_at = CASE WHEN budget_period IS DISTINCT FROM $3 THEN $4 ELSE budget_reset_at END,
		rpm_limit=$5, tpm_limit=$6, max_parallel=$7, updated_at=now() WHERE id::text=$1`,
		id, b.MaxBudget, b.BudgetPeriod, reset, b.RPMLimit, b.TPMLimit, b.MaxParallel)
}
