package alerting

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"lemongate/internal/hooks"
	"lemongate/internal/spend"
)

const (
	budgetCheckEvery = 30 * time.Second // per entity
	watchTick        = 5 * time.Second
	errWindowMinutes = 5
	errMinRequests   = 20
	errEmitEvery     = time.Minute // per model, before dedupe
)

// watcher turns the spend stream into budget and error-rate alerts.
type watcher struct {
	a *Alerter
	w *spend.Writer

	mu        sync.Mutex
	dirty     map[string]bool      // entities with new spend since their last check
	lastCheck map[string]time.Time // entity → last budget check
	errs      map[string]*errWindow
	lastErrEv map[string]time.Time
}

func newWatcher(a *Alerter, w *spend.Writer) *watcher {
	return &watcher{a: a, w: w, dirty: map[string]bool{}, lastCheck: map[string]time.Time{},
		errs: map[string]*errWindow{}, lastErrEv: map[string]time.Time{}}
}

// observe runs synchronously on the request path: only in-memory bookkeeping.
func (wt *watcher) observe(r spend.Record) {
	wt.mu.Lock()
	if r.Cost > 0 {
		for _, e := range [][2]string{{"key", r.KeyID}, {"user", r.UserID}, {"team", r.TeamID}, {"org", r.OrgID}} {
			if e[1] != "" {
				wt.dirty[e[0]+":"+e[1]] = true
			}
		}
	}
	var ev *hooks.Event
	if model := firstNonEmpty(r.ModelGroup, r.Model); model != "" && r.Status != "blocked" {
		win := wt.errs[model]
		if win == nil {
			win = &errWindow{}
			wt.errs[model] = win
		}
		at := r.CreatedAt
		if at.IsZero() {
			at = wt.a.now()
		}
		win.add(at, r.Status == "error")
		threshold := wt.a.settings.Current().Alerting.ErrorRatePercent
		if threshold > 0 && r.Status == "error" {
			total, failed := win.stats(wt.a.now())
			if total >= errMinRequests && float64(failed)*100/float64(total) > float64(threshold) &&
				wt.a.now().Sub(wt.lastErrEv[model]) >= errEmitEvery {
				wt.lastErrEv[model] = wt.a.now()
				e := errorRateEvent(model, total, failed, threshold, r.Error)
				ev = &e
			}
		}
	}
	wt.mu.Unlock()
	if ev != nil {
		wt.a.Emit(*ev)
	}
}

func errorRateEvent(model string, total, failed, threshold int, sample string) hooks.Event {
	rate := float64(failed) * 100 / float64(total)
	sev := "warning"
	if rate >= min(100, float64(threshold)*2) {
		sev = "critical"
	}
	ev := hooks.Event{Kind: "error_rate", Severity: sev, DedupeKey: "error_rate:" + model,
		Title: fmt.Sprintf("High error rate on %s: %.0f%%", model, rate),
		Body: fmt.Sprintf("%d of the last %d requests to %s failed in the past %d minutes (threshold %d%%).",
			failed, total, model, errWindowMinutes, threshold),
		Fields: map[string]string{"model": model, "error_rate": fmt.Sprintf("%.1f%%", rate), "requests": fmt.Sprint(total),
			"errors": fmt.Sprint(failed), "threshold": fmt.Sprintf("%d%%", threshold)}}
	if sample != "" {
		ev.Fields["last_error"] = truncate(sample, 300)
	}
	return ev
}

// run checks dirty entities' budgets, each at most once per budgetCheckEvery.
func (wt *watcher) run(ctx context.Context) {
	t := time.NewTicker(watchTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, e := range wt.due() {
				if err := wt.checkBudget(ctx, e); err != nil && ctx.Err() == nil {
					slog.Warn("budget alert check failed", "entity", e, "err", err)
				}
			}
			wt.gc()
		}
	}
}

func (wt *watcher) due() []string {
	wt.mu.Lock()
	defer wt.mu.Unlock()
	now := wt.a.now()
	var out []string
	for e := range wt.dirty {
		if now.Sub(wt.lastCheck[e]) >= budgetCheckEvery {
			out = append(out, e)
			wt.lastCheck[e] = now
			delete(wt.dirty, e)
		}
		if len(out) >= 500 {
			break
		}
	}
	return out
}

func (wt *watcher) gc() {
	wt.mu.Lock()
	defer wt.mu.Unlock()
	cut := wt.a.now().Add(-10 * time.Minute)
	for e, t := range wt.lastCheck {
		if t.Before(cut) && !wt.dirty[e] {
			delete(wt.lastCheck, e)
		}
	}
	for m, w := range wt.errs {
		if total, _ := w.stats(wt.a.now()); total == 0 {
			delete(wt.errs, m)
		}
	}
}

var budgetQueries = map[string]string{
	"key":  `SELECT COALESCE(NULLIF(alias,''), key_hint), spend, max_budget, budget_period, budget_reset_at FROM api_keys WHERE id::text=$1 AND deleted_at IS NULL`,
	"user": `SELECT email, spend, max_budget, budget_period, budget_reset_at FROM users WHERE id::text=$1`,
	"team": `SELECT name, spend, max_budget, budget_period, budget_reset_at FROM teams WHERE id::text=$1 AND deleted_at IS NULL`,
	"org":  `SELECT name, spend, max_budget, budget_period, budget_reset_at FROM organizations WHERE id::text=$1`,
}

var entityLabels = map[string]string{"key": "Key", "user": "User", "team": "Team", "org": "Organization"}

func (wt *watcher) checkBudget(ctx context.Context, entity string) error {
	typ, id, _ := strings.Cut(entity, ":")
	q, ok := budgetQueries[typ]
	if !ok {
		return nil
	}
	var name, period string
	var spent float64
	var maxBudget *float64
	var resetAt *time.Time
	err := wt.a.pool.QueryRow(ctx, q, id).Scan(&name, &spent, &maxBudget, &period, &resetAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if maxBudget == nil || *maxBudget <= 0 {
		return nil
	}
	spent += wt.w.Pending(entity)
	b := budgetState{Type: typ, ID: id, Name: name, Spend: spent, Max: *maxBudget, Period: period, ResetAt: resetAt}
	ev, ok := budgetEvent(b, wt.a.settings.Current().Alerting.BudgetThresholds)
	if !ok {
		return nil
	}
	// Dedupe for the rest of the budget period (the key embeds the reset time).
	window := 400 * 24 * time.Hour
	if resetAt != nil {
		window = max(time.Until(*resetAt)+time.Hour, time.Hour)
	}
	wt.a.enqueue(envelope{ev: ev, at: wt.a.now(), window: window})
	return nil
}

type budgetState struct {
	Type, ID, Name string
	Spend, Max     float64
	Period         string
	ResetAt        *time.Time
}

// crossedThreshold returns the highest threshold (percent) reached, or 0.
func crossedThreshold(pct float64, thresholds []int) int {
	best := 0
	for _, t := range thresholds {
		if t > 0 && pct >= float64(t) && t > best {
			best = t
		}
	}
	return best
}

// budgetEvent builds the budget_threshold event for the highest crossed threshold.
func budgetEvent(b budgetState, thresholds []int) (hooks.Event, bool) {
	if b.Max <= 0 {
		return hooks.Event{}, false
	}
	pct := b.Spend / b.Max * 100
	t := crossedThreshold(pct, thresholds)
	if t == 0 {
		return hooks.Event{}, false
	}
	sev := "info"
	switch {
	case t >= 100:
		sev = "critical"
	case t >= 80:
		sev = "warning"
	}
	reset := "lifetime"
	if b.ResetAt != nil {
		reset = fmt.Sprint(b.ResetAt.Unix())
	}
	label := entityLabels[b.Type]
	verb := fmt.Sprintf("reached %d%% of its budget", t)
	if t >= 100 {
		verb = "exhausted its budget"
	}
	periodText := "lifetime budget"
	if b.Period != "" {
		periodText = b.Period + " budget"
	}
	body := fmt.Sprintf("%s %q has spent %s of its %s %s (%.1f%%).", label, b.Name, USD(b.Spend), USD(b.Max), periodText, pct)
	if t >= 100 {
		body += " Further requests are rejected until the budget is raised or reset."
	}
	fields := map[string]string{
		strings.ToLower(label): b.Name, "spend": USD(b.Spend), "max_budget": USD(b.Max),
		"used": fmt.Sprintf("%.1f%%", pct), "threshold": fmt.Sprintf("%d%%", t), "period": firstNonEmpty(b.Period, "lifetime"),
	}
	if b.ResetAt != nil {
		fields["resets_at"] = b.ResetAt.UTC().Format("2006-01-02 15:04 UTC")
	}
	return hooks.Event{Kind: "budget_threshold", Severity: sev,
		DedupeKey: fmt.Sprintf("budget:%s:%s:%d:%s", b.Type, b.ID, t, reset),
		Title:     fmt.Sprintf("%s %s %s", label, b.Name, verb), Body: body, Fields: fields}, true
}

// errWindow counts requests and errors in one-minute buckets over errWindowMinutes.
type errWindow struct {
	buckets [errWindowMinutes]struct {
		minute        int64
		total, failed int
	}
}

func (w *errWindow) add(at time.Time, failed bool) {
	m := at.Unix() / 60
	b := &w.buckets[m%errWindowMinutes]
	if b.minute != m {
		b.minute, b.total, b.failed = m, 0, 0
	}
	b.total++
	if failed {
		b.failed++
	}
}

func (w *errWindow) stats(now time.Time) (total, failed int) {
	cur := now.Unix() / 60
	for _, b := range w.buckets {
		if b.minute > cur-errWindowMinutes && b.minute <= cur {
			total += b.total
			failed += b.failed
		}
	}
	return
}

func firstNonEmpty(v ...string) string {
	if i := slices.IndexFunc(v, func(s string) bool { return s != "" }); i >= 0 {
		return v[i]
	}
	return ""
}

// USD formats money with cents, or more precision for sub-cent amounts.
func USD(v float64) string {
	if v != 0 && v < 0.01 && v > -0.01 {
		s := strings.TrimRight(fmt.Sprintf("%.6f", v), "0")
		return "$" + s
	}
	return "$" + commas(fmt.Sprintf("%.2f", v))
}

func commas(s string) string {
	intPart, frac, _ := strings.Cut(s, ".")
	neg := strings.HasPrefix(intPart, "-")
	intPart = strings.TrimPrefix(intPart, "-")
	var b strings.Builder
	for i, c := range intPart {
		if i > 0 && (len(intPart)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	out := b.String()
	if neg {
		out = "-" + out
	}
	if frac != "" {
		out += "." + frac
	}
	return out
}
