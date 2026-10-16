package analytics

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Scoped reports whether the filter is restricted to a member's own keys/teams.
func (f Filter) Scoped() bool {
	return f.KeyIDs != nil || f.TeamIDs != nil || f.ScopeUserID != ""
}

// RestrictToUser scopes the filter to traffic a member may see: requests made with
// keys they own, by their teams, or attributed to them directly (e.g. playground).
func (f *Filter) RestrictToUser(ctx context.Context, pool *pgxpool.Pool, userID string, teamIDs []string) {
	f.KeyIDs = UserKeyIDs(ctx, pool, userID)
	f.TeamIDs = append([]string{}, teamIDs...)
	f.ScopeUserID = userID
	if f.ScopeUserID == "" {
		// Defensive: a scoped filter without a user must still match nothing extra.
		f.ScopeUserID = "-"
	}
}

// UserKeyIDs lists the IDs of keys owned by a user (including deleted ones, so
// historical traffic stays visible).
func UserKeyIDs(ctx context.Context, pool *pgxpool.Pool, userID string) []string {
	out := []string{}
	if userID == "" {
		return out
	}
	rows, err := pool.Query(ctx, `SELECT id::text FROM api_keys WHERE user_id = $1::uuid`, userID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			out = append(out, id)
		}
	}
	return out
}

// Previous returns the equally long period immediately before f (same scope).
func (f Filter) Previous() Filter {
	days := int(truncDay(f.To).Sub(truncDay(f.From)).Hours()/24) + 1
	p := f
	p.To = truncDay(f.From).AddDate(0, 0, -1)
	p.From = p.To.AddDate(0, 0, -(days - 1))
	return p
}

// Days is the number of calendar days covered by the filter.
func (f Filter) Days() int {
	return int(truncDay(f.To).Sub(truncDay(f.From)).Hours()/24) + 1
}

// Range builds a filter from inclusive UTC dates.
func Range(from, to time.Time) Filter {
	if to.Before(from) {
		from, to = to, from
	}
	return Filter{From: truncDay(from), To: truncDay(to)}
}
