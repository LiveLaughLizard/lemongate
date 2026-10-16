// Package alerting delivers operational alerts to Slack, Mattermost, generic webhooks and email.
//
// Producers call Emit (non-blocking); a single worker deduplicates events against
// alert_history, fans them out to every matching enabled channel and records each
// delivery attempt. Watch derives budget-threshold and error-rate events from the
// spend stream; Run schedules key-expiry checks and the daily spend report.
package alerting

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"lemongate/internal/config"
	"lemongate/internal/hooks"
	"lemongate/internal/metrics"
	"lemongate/internal/secret"
	"lemongate/internal/settings"
	"lemongate/internal/spend"
)

// Event kinds understood by the console (subscription checkboxes) and the API.
var EventKinds = []EventKind{
	{"budget_threshold", "Budget thresholds", "A key, user, team or organization crossed a budget threshold."},
	{"key_expiring", "Key expiring", "An API key expires soon."},
	{"deployment_down", "Deployment down", "A vLLM deployment failed its health check."},
	{"deployment_up", "Deployment recovered", "A deployment is healthy again."},
	{"error_rate", "High error rate", "A model's error rate over 5 minutes is above the threshold."},
	{"slow_response", "Slow responses", "A request took longer than the slow-response threshold."},
	{"daily_report", "Daily spend report", "Yesterday's totals, top models, keys and teams."},
}

type EventKind struct{ Key, Label, Description string }

// Severities in ascending order.
var Severities = []string{"info", "warning", "critical"}

// SeverityRank maps a severity to its order (unknown → info).
func SeverityRank(s string) int {
	if i := slices.Index(Severities, s); i >= 0 {
		return i
	}
	return 0
}

const queueSize = 1024

// envelope is a queued event plus delivery options.
type envelope struct {
	ev     hooks.Event
	at     time.Time
	window time.Duration // dedupe window override (0 = settings default)
}

// Alerter implements hooks.Alerter.
type Alerter struct {
	pool     *pgxpool.Pool
	box      *secret.Box
	settings *settings.Store
	smtp     config.SMTPConfig
	client   *http.Client

	queue chan envelope

	mu          sync.Mutex
	recent      map[string]time.Time // dedupe key → last processed (in-memory fast path)
	dropped     int
	lastDropLog time.Time

	watch *watcher

	// now is replaceable in tests.
	now func() time.Time
	// sendHook, when set, replaces real delivery (tests).
	sendHook func(ctx context.Context, ch Channel, m Message) error
	// channels, when set, replaces loading channels from the database (tests).
	channels func(ctx context.Context) ([]Channel, error)
}

func New(pool *pgxpool.Pool, box *secret.Box, st *settings.Store, smtp config.SMTPConfig) *Alerter {
	return &Alerter{pool: pool, box: box, settings: st, smtp: smtp,
		client: &http.Client{Timeout: 15 * time.Second},
		queue:  make(chan envelope, queueSize), recent: map[string]time.Time{}, now: time.Now}
}

// SMTPEnabled reports whether email channels can deliver.
func (a *Alerter) SMTPEnabled() bool { return a.smtp.Enabled() }

// Emit queues an event for delivery. It never blocks; if the queue is full the
// event is dropped with a warning.
func (a *Alerter) Emit(ev hooks.Event) { a.enqueue(envelope{ev: ev, at: a.now()}) }

func (a *Alerter) enqueue(e envelope) {
	if e.ev.Severity == "" {
		e.ev.Severity = "info"
	}
	select {
	case a.queue <- e:
	default:
		a.mu.Lock()
		a.dropped++
		logIt := a.now().Sub(a.lastDropLog) > time.Minute
		if logIt {
			a.lastDropLog = a.now()
		}
		n := a.dropped
		a.mu.Unlock()
		if logIt {
			slog.Warn("alert queue full; dropping events", "kind", e.ev.Kind, "title", e.ev.Title, "dropped_total", n)
		}
	}
}

// Run processes the queue and runs scheduled checks until ctx is cancelled.
func (a *Alerter) Run(ctx context.Context) {
	go a.schedule(ctx)
	if a.watch != nil {
		go a.watch.run(ctx)
	}
	for {
		select {
		case e := <-a.queue:
			a.process(ctx, e)
		case <-ctx.Done():
			// Best-effort drain so shutdown-time events (e.g. a final health
			// transition) are not lost silently.
			dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			for {
				select {
				case e := <-a.queue:
					a.process(dctx, e)
				default:
					return
				}
			}
		}
	}
}

// process deduplicates, delivers and records one event.
func (a *Alerter) process(ctx context.Context, e envelope) {
	ev := e.ev
	window := e.window
	if window == 0 {
		window = time.Duration(max(a.settings.Current().Alerting.DedupeMinutes, 0)) * time.Minute
	}
	if ev.DedupeKey != "" && window > 0 && ev.Kind != "test" {
		if a.seenRecently(ev.DedupeKey, window) {
			return
		}
		dup, err := a.dedupeHit(ctx, ev.DedupeKey, window)
		if err != nil {
			slog.Warn("alert dedupe check failed", "err", err)
		} else if dup {
			a.markSeen(ev.DedupeKey)
			return
		}
		a.markSeen(ev.DedupeKey)
	}
	load := a.ListChannels
	if a.channels != nil {
		load = a.channels
	}
	chans, err := load(ctx)
	if err != nil {
		slog.Error("load alert channels", "err", err)
		return
	}
	var targets []Channel
	for _, ch := range chans {
		if ch.Matches(ev) {
			targets = append(targets, ch)
		}
	}
	msg := Message{Event: ev, At: e.at}
	if len(targets) == 0 {
		// Keep a record so the console shows what fired and dedupe survives restarts.
		a.record(ctx, msg, nil, nil)
		return
	}
	var wg sync.WaitGroup
	for _, ch := range targets {
		wg.Add(1)
		go func(ch Channel) {
			defer wg.Done()
			err := a.deliver(ctx, ch, msg)
			if err != nil {
				slog.Warn("alert delivery failed", "channel", ch.Name, "kind", ev.Kind, "err", err)
			}
			a.record(ctx, msg, &ch, err)
		}(ch)
	}
	wg.Wait()
}

func (a *Alerter) seenRecently(key string, window time.Duration) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	t, ok := a.recent[key]
	return ok && a.now().Sub(t) < window
}

func (a *Alerter) markSeen(key string) {
	a.mu.Lock()
	a.recent[key] = a.now()
	a.mu.Unlock()
}

// pruneRecent drops in-memory dedupe entries older than maxAge.
func (a *Alerter) pruneRecent(maxAge time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	cut := a.now().Add(-maxAge)
	for k, t := range a.recent {
		if t.Before(cut) {
			delete(a.recent, k)
		}
	}
}

func (a *Alerter) dedupeHit(ctx context.Context, key string, window time.Duration) (bool, error) {
	if a.pool == nil {
		return false, nil
	}
	var hit bool
	err := a.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM alert_history WHERE dedupe_key = $1 AND at > $2)`,
		key, a.now().Add(-window)).Scan(&hit)
	return hit, err
}

// deliver sends a message through one channel with a per-channel timeout.
func (a *Alerter) deliver(ctx context.Context, ch Channel, m Message) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if a.sendHook != nil {
		return a.sendHook(ctx, ch, m)
	}
	switch ch.Kind {
	case KindSlack:
		return a.sendSlack(ctx, ch.Config, m)
	case KindMattermost:
		return a.sendMattermost(ctx, ch.Config, m)
	case KindWebhook:
		return a.sendWebhook(ctx, ch.Config, m)
	case KindEmail:
		return a.sendEmail(ctx, ch.Config, m)
	}
	return fmt.Errorf("unknown channel kind %q", ch.Kind)
}

func (a *Alerter) record(ctx context.Context, m Message, ch *Channel, sendErr error) {
	if ch != nil {
		result := "ok"
		if sendErr != nil {
			result = "error"
		}
		metrics.AlertsSent.WithLabelValues(string(ch.Kind), result).Inc()
	}
	if a.pool == nil {
		return
	}
	name, errText := "", ""
	if ch != nil {
		name = ch.Name
	}
	if sendErr != nil {
		errText = truncate(sendErr.Error(), 1000)
	}
	ctx = context.WithoutCancel(ctx)
	if _, err := a.pool.Exec(ctx, `INSERT INTO alert_history (at, event, severity, title, body, dedupe_key, channel, ok, error)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, m.At, m.Event.Kind, m.Event.Severity, truncate(m.Event.Title, 500),
		truncate(m.Body(), 8000), m.Event.DedupeKey, name, sendErr == nil, errText); err != nil {
		slog.Error("record alert history", "err", err)
	}
}

// SendTest delivers a test event directly to one channel (bypassing the queue,
// subscriptions and dedupe) and records the attempt.
func (a *Alerter) SendTest(ctx context.Context, channelID, actor string) error {
	ch, err := a.GetChannel(ctx, channelID)
	if err != nil {
		return err
	}
	if ch.ConfigErr != nil {
		return fmt.Errorf("channel configuration is unreadable: %w", ch.ConfigErr)
	}
	ev := hooks.Event{Kind: "test", Severity: "info", Title: "Test alert from LemonGate",
		Body:   fmt.Sprintf("This is a test notification for channel %q. If you can read this, delivery works.", ch.Name),
		Fields: map[string]string{"channel": ch.Name, "kind": string(ch.Kind)}}
	if actor != "" {
		ev.Fields["sent_by"] = actor
	}
	m := Message{Event: ev, At: a.now()}
	sendErr := a.deliver(ctx, ch, m)
	a.record(ctx, m, &ch, sendErr)
	return sendErr
}

// ErrNotFound is returned for unknown channels.
var ErrNotFound = errors.New("alert channel not found")

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Watch subscribes to spend records to derive budget-threshold and error-rate alerts.
// The callback is cheap: it only updates in-memory counters; database checks run
// asynchronously in the loop started by Run.
func (a *Alerter) Watch(w *spend.Writer) {
	a.watch = newWatcher(a, w)
	w.Observe(a.watch.observe)
}
