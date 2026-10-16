package spend

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"lemongate/internal/store"
)

// ResetBudgets zeroes spend for every entity whose budget period has elapsed.
func ResetBudgets(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	total := 0
	for _, table := range []string{"api_keys", "users", "teams", "organizations", "end_users", "tags"} {
		idCol := "id"
		if table == "tags" {
			idCol = "name"
		}
		rows, err := pool.Query(ctx, `SELECT `+idCol+`::text, budget_period FROM `+table+` WHERE budget_reset_at IS NOT NULL AND budget_reset_at <= now()`)
		if err != nil {
			return total, err
		}
		type due struct{ id, period string }
		var list []due
		for rows.Next() {
			var d due
			if err := rows.Scan(&d.id, &d.period); err == nil {
				list = append(list, d)
			}
		}
		rows.Close()
		for _, d := range list {
			next := store.NextReset(d.period, time.Now())
			if _, err := pool.Exec(ctx, `UPDATE `+table+` SET spend = 0, budget_reset_at = $2 WHERE `+idCol+`::text = $1`, d.id, next); err != nil {
				return total, err
			}
			if table == "teams" {
				_, _ = pool.Exec(ctx, `UPDATE team_members SET spend = 0 WHERE team_id::text = $1`, d.id)
			}
			total++
		}
	}
	return total, nil
}

// PurgeOld removes log rows older than the retention window.
func PurgeOld(ctx context.Context, pool *pgxpool.Pool, retentionDays int) {
	if retentionDays <= 0 {
		return
	}
	cut := time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	for _, q := range []string{
		`DELETE FROM request_logs WHERE created_at < $1`,
		`DELETE FROM health_checks WHERE checked_at < $1`,
		`DELETE FROM guardrail_events WHERE at < $1`,
		`DELETE FROM mcp_tool_calls WHERE at < $1`,
		`DELETE FROM alert_history WHERE at < $1`,
	} {
		if _, err := pool.Exec(ctx, q, cut); err != nil {
			slog.Warn("retention purge failed", "err", err)
		}
	}
	_, _ = pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at < now()`)
}
