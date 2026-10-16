package alerting

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"lemongate/internal/analytics"
	"lemongate/internal/hooks"
)

const historyRetention = 90 * 24 * time.Hour

// schedule runs periodic checks: key expiry (hourly), the daily report (checked
// every minute, sent once per UTC day) and housekeeping.
func (a *Alerter) schedule(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	// First expiry check shortly after start, then hourly.
	nextExpiry := a.now().Add(30 * time.Second)
	var lastPrune time.Time
	for {
		now := a.now()
		if !now.Before(nextExpiry) {
			nextExpiry = now.Add(time.Hour)
			if err := a.CheckKeyExpiry(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("key expiry check failed", "err", err)
			}
		}
		if err := a.maybeDailyReport(ctx, now); err != nil && ctx.Err() == nil {
			slog.Warn("daily report failed", "err", err)
		}
		if now.Sub(lastPrune) > 6*time.Hour {
			lastPrune = now
			a.pruneRecent(48 * time.Hour)
			if _, err := a.pool.Exec(ctx, `DELETE FROM alert_history WHERE at < $1`, now.Add(-historyRetention)); err != nil && ctx.Err() == nil {
				slog.Warn("prune alert history", "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-time.After(time.Until(nextExpiry)):
		}
	}
}

// CheckKeyExpiry emits key_expiring for every active key expiring within the
// configured window. Each key alerts once per expiry date.
func (a *Alerter) CheckKeyExpiry(ctx context.Context) error {
	days := a.settings.Current().Alerting.KeyExpiryDays
	if days <= 0 {
		return nil
	}
	rows, err := a.pool.Query(ctx, `SELECT k.id::text, COALESCE(NULLIF(k.alias,''), k.key_hint), k.key_hint, k.expires_at,
		COALESCE(u.email,''), COALESCE(t.name,'')
		FROM api_keys k LEFT JOIN users u ON u.id = k.user_id LEFT JOIN teams t ON t.id = k.team_id
		WHERE k.deleted_at IS NULL AND NOT k.blocked AND k.expires_at > $1 AND k.expires_at <= $2
		ORDER BY k.expires_at`, a.now(), a.now().Add(time.Duration(days)*24*time.Hour))
	if err != nil {
		return err
	}
	type exp struct {
		id, label, hint, owner, team string
		at                           time.Time
	}
	var list []exp
	for rows.Next() {
		var e exp
		if err := rows.Scan(&e.id, &e.label, &e.hint, &e.at, &e.owner, &e.team); err != nil {
			rows.Close()
			return err
		}
		list = append(list, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, e := range list {
		left := e.at.Sub(a.now())
		sev := "warning"
		if left < 24*time.Hour {
			sev = "critical"
		}
		ev := hooks.Event{Kind: "key_expiring", Severity: sev,
			DedupeKey: fmt.Sprintf("key_expiring:%s:%d", e.id, e.at.Unix()),
			Title:     fmt.Sprintf("API key %s expires %s", e.label, humanUntil(left)),
			Body: fmt.Sprintf("The API key %q (%s) expires on %s. Regenerate it or extend its expiry to avoid failed requests.",
				e.label, e.hint, e.at.UTC().Format("Mon Jan 2, 2006 15:04 UTC")),
			Fields: map[string]string{"key": e.label, "key_hint": e.hint, "expires_at": e.at.UTC().Format("2006-01-02 15:04 UTC")}}
		if e.owner != "" {
			ev.Fields["owner"] = e.owner
		}
		if e.team != "" {
			ev.Fields["team"] = e.team
		}
		a.enqueue(envelope{ev: ev, at: a.now(), window: time.Duration(days+1) * 24 * time.Hour})
	}
	return nil
}

func humanUntil(d time.Duration) string {
	switch {
	case d < time.Hour:
		return "in under an hour"
	case d < 24*time.Hour:
		return fmt.Sprintf("in %d hours", int(d.Hours()))
	case d < 48*time.Hour:
		return "tomorrow"
	}
	return fmt.Sprintf("in %d days", int(d.Hours()/24))
}

// maybeDailyReport sends yesterday's report once per UTC day after the configured hour.
// The history row (dedupe key daily_report:<date>) is the durable "already sent" marker.
func (a *Alerter) maybeDailyReport(ctx context.Context, now time.Time) error {
	s := a.settings.Current().Alerting
	now = now.UTC()
	if !s.DailyReport || now.Hour() < s.DailyReportHourUTC {
		return nil
	}
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -1)
	key := "daily_report:" + day.Format("2006-01-02")
	if a.seenRecently(key, 48*time.Hour) {
		return nil
	}
	var sent bool
	if err := a.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM alert_history WHERE dedupe_key = $1)`, key).Scan(&sent); err != nil {
		return err
	}
	if sent {
		a.markSeen(key)
		return nil
	}
	ev, err := a.DailyReport(ctx, day)
	if err != nil {
		return err
	}
	a.markSeen(key) // claim before queueing so the next tick does not rebuild it
	a.enqueue(envelope{ev: ev, at: a.now(), window: -1})
	return nil
}

// DailyReport builds the spend digest for one UTC day.
func (a *Alerter) DailyReport(ctx context.Context, day time.Time) (hooks.Event, error) {
	f := analytics.Filter{From: day, To: day}
	tot, err := analytics.GetTotals(ctx, a.pool, f)
	if err != nil {
		return hooks.Event{}, err
	}
	top := func(by string) []analytics.Row {
		rows, err := analytics.Breakdown(ctx, a.pool, f, by, 5)
		if err != nil {
			slog.Warn("daily report breakdown", "by", by, "err", err)
		}
		return rows
	}
	models, keys, teams := top("model"), top("key"), top("team")
	return reportEvent(day, tot, models, keys, teams), nil
}

func reportEvent(day time.Time, tot analytics.Totals, models, keys, teams []analytics.Row) hooks.Event {
	var b strings.Builder
	dayLabel := day.Format("Mon Jan 2, 2006")
	if tot.Requests == 0 {
		fmt.Fprintf(&b, "No requests were served on %s.", dayLabel)
	} else {
		fmt.Fprintf(&b, "%s: %s across %s requests (%.1f%% errors), %s tokens, %.0f ms average latency.",
			dayLabel, USD(tot.Cost), commas(fmt.Sprint(tot.Requests)), tot.ErrorRate(), compact(tot.Tokens()), tot.AvgLatencyMs)
	}
	section := func(title string, rows []analytics.Row) {
		if len(rows) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n\nTop %s\n", title)
		for i, r := range rows {
			if i > 0 {
				b.WriteString("\n")
			}
			fmt.Fprintf(&b, "• %s — %s · %s requests", firstNonEmpty(r.Label, r.Key), USD(r.Cost), commas(fmt.Sprint(r.Requests)))
		}
	}
	section("models", models)
	section("keys", keys)
	section("teams", teams)
	fields := map[string]string{
		"date": day.Format("2006-01-02"), "spend": USD(tot.Cost), "requests": commas(fmt.Sprint(tot.Requests)),
		"tokens": compact(tot.Tokens()), "error_rate": fmt.Sprintf("%.1f%%", tot.ErrorRate()),
	}
	if len(models) > 0 {
		fields["top_model"] = models[0].Label
	}
	return hooks.Event{Kind: "daily_report", Severity: "info", DedupeKey: "daily_report:" + day.Format("2006-01-02"),
		Title: "Daily spend report · " + day.Format("Jan 2, 2006"), Body: b.String(), Fields: fields}
}

func compact(n int64) string {
	f := float64(n)
	switch {
	case f >= 1e9:
		return fmt.Sprintf("%.1fB", f/1e9)
	case f >= 1e6:
		return fmt.Sprintf("%.1fM", f/1e6)
	case f >= 1e3:
		return fmt.Sprintf("%.1fK", f/1e3)
	}
	return fmt.Sprint(n)
}
