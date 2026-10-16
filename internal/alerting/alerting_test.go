package alerting

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"lemongate/internal/analytics"
	"lemongate/internal/config"
	"lemongate/internal/hooks"
	"lemongate/internal/secret"
	"lemongate/internal/settings"
	"lemongate/internal/spend"
)

func testAlerter(t *testing.T, chans ...Channel) (*Alerter, *[]Message) {
	t.Helper()
	box, _ := secret.New("test")
	a := New(nil, box, settings.NewStore(nil), configSMTP())
	var mu sync.Mutex
	sent := &[]Message{}
	a.channels = func(context.Context) ([]Channel, error) { return chans, nil }
	a.sendHook = func(_ context.Context, ch Channel, m Message) error {
		mu.Lock()
		defer mu.Unlock()
		*sent = append(*sent, m)
		return nil
	}
	return a, sent
}

func configSMTP() config.SMTPConfig { return config.SMTPConfig{} }

func TestDedupeWithinWindow(t *testing.T) {
	ch := Channel{Name: "ops", Kind: KindWebhook, Enabled: true, MinSeverity: "info"}
	a, sent := testAlerter(t, ch)
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return now }
	ev := hooks.Event{Kind: "deployment_down", Severity: "critical", Title: "down", DedupeKey: "dep-down:1"}
	ctx := context.Background()
	a.process(ctx, envelope{ev: ev, at: now})
	a.process(ctx, envelope{ev: ev, at: now})
	if len(*sent) != 1 {
		t.Fatalf("expected 1 delivery within dedupe window, got %d", len(*sent))
	}
	// A different key is not deduplicated.
	ev2 := ev
	ev2.DedupeKey = "dep-down:2"
	a.process(ctx, envelope{ev: ev2, at: now})
	if len(*sent) != 2 {
		t.Fatalf("expected distinct key to deliver, got %d", len(*sent))
	}
	// After the window (default 60 minutes) the same key delivers again.
	now = now.Add(61 * time.Minute)
	a.process(ctx, envelope{ev: ev, at: now})
	if len(*sent) != 3 {
		t.Fatalf("expected re-delivery after window, got %d", len(*sent))
	}
	// Events without a dedupe key are never suppressed.
	noKey := hooks.Event{Kind: "deployment_down", Severity: "critical", Title: "x"}
	a.process(ctx, envelope{ev: noKey, at: now})
	a.process(ctx, envelope{ev: noKey, at: now})
	if len(*sent) != 5 {
		t.Fatalf("expected events without dedupe key to always deliver, got %d", len(*sent))
	}
}

func TestDedupeWindowOverride(t *testing.T) {
	a, sent := testAlerter(t, Channel{Name: "c", Kind: KindSlack, Enabled: true})
	now := time.Now()
	a.now = func() time.Time { return now }
	ev := hooks.Event{Kind: "budget_threshold", Severity: "warning", Title: "b", DedupeKey: "budget:key:1:80:lifetime"}
	a.process(context.Background(), envelope{ev: ev, at: now, window: 30 * 24 * time.Hour})
	now = now.Add(5 * 24 * time.Hour)
	a.process(context.Background(), envelope{ev: ev, at: now, window: 30 * 24 * time.Hour})
	if len(*sent) != 1 {
		t.Fatalf("expected long window to suppress, got %d", len(*sent))
	}
}

func TestEmitNonBlocking(t *testing.T) {
	a, _ := testAlerter(t)
	done := make(chan struct{})
	go func() {
		for i := 0; i < queueSize*2; i++ {
			a.Emit(hooks.Event{Kind: "test", Title: "x"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Emit blocked with no consumer")
	}
}

func TestChannelMatches(t *testing.T) {
	c := Channel{Enabled: true, MinSeverity: "warning", Events: []string{"budget_threshold", "deployment_down"}}
	cases := []struct {
		ev   hooks.Event
		want bool
	}{
		{hooks.Event{Kind: "budget_threshold", Severity: "warning"}, true},
		{hooks.Event{Kind: "budget_threshold", Severity: "critical"}, true},
		{hooks.Event{Kind: "budget_threshold", Severity: "info"}, false},
		{hooks.Event{Kind: "key_expiring", Severity: "critical"}, false},
	}
	for _, tc := range cases {
		if got := c.Matches(tc.ev); got != tc.want {
			t.Errorf("Matches(%+v) = %v, want %v", tc.ev, got, tc.want)
		}
	}
	all := Channel{Enabled: true, MinSeverity: "info"}
	if !all.Matches(hooks.Event{Kind: "anything", Severity: "info"}) {
		t.Error("empty event list should match every event")
	}
	all.Enabled = false
	if all.Matches(hooks.Event{Kind: "x", Severity: "critical"}) {
		t.Error("disabled channel must not match")
	}
}

func TestSlackPayload(t *testing.T) {
	m := Message{At: time.Unix(1700000000, 0), Event: hooks.Event{Kind: "deployment_down", Severity: "critical",
		Title: "Deployment down: llama", Body: "it broke", Fields: map[string]string{"model": "llama", "api_base": "http://x"}}}
	s := string(marshal(SlackPayload(m, "<!channel>")))
	for _, want := range []string{`"color":"#E5484D"`, `:rotating_light: Deployment down: llama`, `<!channel> it broke`,
		`*Api base*\nhttp://x`, `deployment_down`, `"type":"header"`} {
		if !strings.Contains(s, want) {
			t.Errorf("slack payload missing %q:\n%s", want, s)
		}
	}
	m.Event.Severity = "info"
	if strings.Contains(string(marshal(SlackPayload(m, "<!channel>"))), "<!channel>") {
		t.Error("mention should only apply to critical alerts")
	}
}

func TestWebhookSignatureAndDelivery(t *testing.T) {
	var got struct {
		body []byte
		h    http.Header
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.body, _ = io.ReadAll(r.Body)
		got.h = r.Header.Clone()
	}))
	defer srv.Close()
	box, _ := secret.New("k")
	a := New(nil, box, settings.NewStore(nil), configSMTP())
	m := Message{At: time.Unix(1700000000, 0), Event: hooks.Event{Kind: "test", Severity: "info", Title: "hello", Fields: map[string]string{"a": "b"}}}
	cfg := ChannelConfig{URL: srv.URL, Secret: "s3cret", Headers: map[string]string{"X-Team": "ml"}}
	if err := a.sendWebhook(context.Background(), cfg, m); err != nil {
		t.Fatal(err)
	}
	if got.h.Get("X-Team") != "ml" || got.h.Get("Content-Type") != "application/json" {
		t.Errorf("headers not forwarded: %v", got.h)
	}
	ts := got.h.Get(TimestampHeader)
	if ts != "1700000000" {
		t.Errorf("timestamp header = %q", ts)
	}
	if !VerifySignature("s3cret", ts, got.body, got.h.Get(SignatureHeader)) {
		t.Errorf("signature does not verify: %s", got.h.Get(SignatureHeader))
	}
	if VerifySignature("wrong", ts, got.body, got.h.Get(SignatureHeader)) {
		t.Error("signature verified with the wrong secret")
	}
	var p WebhookPayload
	if err := json.Unmarshal(got.body, &p); err != nil {
		t.Fatal(err)
	}
	if p.Event != "test" || p.Title != "hello" || p.Fields["a"] != "b" || p.Timestamp != "2023-11-14T22:13:20Z" || p.Body != "hello" {
		t.Errorf("unexpected payload %+v", p)
	}
	if s := Sign("key", "1", []byte("{}")); !strings.HasPrefix(s, "sha256=") || len(s) != 7+64 {
		t.Errorf("unexpected signature format %q", s)
	}
}

func TestWebhookErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer srv.Close()
	box, _ := secret.New("k")
	a := New(nil, box, settings.NewStore(nil), configSMTP())
	err := a.sendWebhook(context.Background(), ChannelConfig{URL: srv.URL}, Message{At: time.Now(), Event: hooks.Event{Title: "x"}})
	if err == nil || !strings.Contains(err.Error(), "HTTP 502") {
		t.Fatalf("expected HTTP 502 error, got %v", err)
	}
}

func TestDeliveryErrorHidesWebhookURL(t *testing.T) {
	box, _ := secret.New("k")
	a := New(nil, box, settings.NewStore(nil), configSMTP())
	m := Message{At: time.Now(), Event: hooks.Event{Title: "x"}}
	for _, c := range []struct{ url, want string }{
		{"http://127.0.0.1:1/services/T000/B000/s3cretT0ken?token=q", `Post "http://127.0.0.1:1/…"`},
		{"http://bad host/services/s3cretT0ken", `parse "…"`},
	} {
		err := a.sendSlack(context.Background(), ChannelConfig{URL: c.url}, m)
		if err == nil || strings.Contains(err.Error(), "s3cretT0ken") || strings.Contains(err.Error(), "token=") ||
			!strings.HasPrefix(err.Error(), c.want) {
			t.Fatalf("%s: error = %v", c.url, err)
		}
	}
}

func TestEmailFormatting(t *testing.T) {
	m := Message{At: time.Unix(1700000000, 0), Event: hooks.Event{Kind: "budget_threshold", Severity: "warning",
		Title: "Key <prod> reached 80%", Body: "spent a lot", Fields: map[string]string{"spend": "$8.00"}}}
	if s := EmailSubject(m); s != "[LemonGate] [WARNING] Key <prod> reached 80%" {
		t.Errorf("subject = %q", s)
	}
	h := EmailHTML(m)
	if !strings.Contains(h, "Key &lt;prod&gt; reached 80%") || strings.Contains(h, "<prod>") {
		t.Error("HTML body must escape content")
	}
	if !strings.Contains(EmailText(m), "Spend: $8.00") {
		t.Error("text body missing fields")
	}
	raw := string(BuildEmail("alerts@example.com", []string{"a@example.com", "b@example.com"}, m))
	for _, want := range []string{"To: a@example.com, b@example.com", "multipart/alternative", "text/plain; charset=utf-8", "text/html; charset=utf-8"} {
		if !strings.Contains(raw, want) {
			t.Errorf("email missing %q", want)
		}
	}
}

func TestEmailWithoutSMTP(t *testing.T) {
	box, _ := secret.New("k")
	a := New(nil, box, settings.NewStore(nil), configSMTP())
	if err := a.sendEmail(context.Background(), ChannelConfig{Recipients: []string{"x@y.z"}}, Message{}); err != ErrSMTPDisabled {
		t.Fatalf("expected ErrSMTPDisabled, got %v", err)
	}
}

func TestConfigValidate(t *testing.T) {
	if err := (ChannelConfig{URL: "ftp://x"}).Validate(KindSlack); err == nil {
		t.Error("non-http URL accepted")
	}
	if err := (ChannelConfig{URL: "https://hooks.example.com/T/B/x"}).Validate(KindSlack); err != nil {
		t.Error(err)
	}
	if err := (ChannelConfig{URL: "https://x.io", Headers: map[string]string{"bad header": "v"}}).Validate(KindWebhook); err == nil {
		t.Error("invalid header accepted")
	}
	if err := (ChannelConfig{Recipients: []string{"not-an-email"}}).Validate(KindEmail); err == nil {
		t.Error("invalid email accepted")
	}
	if err := (ChannelConfig{}).Validate(KindEmail); err == nil {
		t.Error("empty recipients accepted")
	}
}

func TestRedactURL(t *testing.T) {
	if got := RedactURL("https://hooks.example.com/services/T000/B000/abcdefgh"); got != "https://hooks.example.com/…efgh" {
		t.Errorf("RedactURL = %q", got)
	}
	if got := RedactURL("https://x.io"); got != "https://x.io" {
		t.Errorf("RedactURL = %q", got)
	}
}

func TestBudgetEvent(t *testing.T) {
	th := []int{50, 80, 100}
	if crossedThreshold(49.9, th) != 0 || crossedThreshold(50, th) != 50 || crossedThreshold(99, th) != 80 || crossedThreshold(250, th) != 100 {
		t.Error("crossedThreshold wrong")
	}
	reset := time.Unix(1800000000, 0)
	ev, ok := budgetEvent(budgetState{Type: "key", ID: "k1", Name: "bot", Spend: 8.5, Max: 10, Period: "monthly", ResetAt: &reset}, th)
	if !ok || ev.Severity != "warning" || ev.DedupeKey != "budget:key:k1:80:1800000000" || ev.Kind != "budget_threshold" {
		t.Errorf("unexpected event %+v", ev)
	}
	if !strings.Contains(ev.Title, "reached 80%") || ev.Fields["key"] != "bot" || ev.Fields["used"] != "85.0%" {
		t.Errorf("unexpected content %+v", ev)
	}
	ev, _ = budgetEvent(budgetState{Type: "team", ID: "t", Name: "ml", Spend: 12, Max: 10}, th)
	if ev.Severity != "critical" || !strings.HasSuffix(ev.DedupeKey, ":100:lifetime") || !strings.Contains(ev.Title, "exhausted") {
		t.Errorf("unexpected 100%% event %+v", ev)
	}
	if _, ok := budgetEvent(budgetState{Type: "key", Spend: 1, Max: 10}, th); ok {
		t.Error("no threshold crossed should not emit")
	}
}

func TestErrWindow(t *testing.T) {
	var w errWindow
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		w.add(base.Add(time.Duration(i)*time.Minute), i%2 == 0)
	}
	total, failed := w.stats(base.Add(9 * time.Minute))
	if total != 5 || failed != 2 { // minutes 5..9: errors at 6, 8
		t.Errorf("stats = %d/%d, want 5/2", total, failed)
	}
	total, _ = w.stats(base.Add(30 * time.Minute))
	if total != 0 {
		t.Errorf("stale buckets counted: %d", total)
	}
}

func TestErrorRateObserve(t *testing.T) {
	a, _ := testAlerter(t)
	w := spend.NewWriter(nil)
	a.Watch(w)
	now := time.Now()
	for i := 0; i < 30; i++ {
		status := "success"
		if i%2 == 0 {
			status = "error"
		}
		a.watch.observe(spend.Record{CreatedAt: now, ModelGroup: "llama", Status: status, Error: "boom"})
	}
	if len(a.queue) != 1 {
		t.Fatalf("expected exactly one error_rate event queued, got %d", len(a.queue))
	}
	e := <-a.queue
	if e.ev.Kind != "error_rate" || e.ev.DedupeKey != "error_rate:llama" || e.ev.Fields["last_error"] != "boom" {
		t.Errorf("unexpected event %+v", e.ev)
	}
}

func TestBudgetDirtyTracking(t *testing.T) {
	a, _ := testAlerter(t)
	w := spend.NewWriter(nil)
	a.Watch(w)
	a.watch.observe(spend.Record{Cost: 0.1, KeyID: "k", TeamID: "t", Status: "success", ModelGroup: "m"})
	due := a.watch.due()
	if len(due) != 2 {
		t.Fatalf("expected key and team due, got %v", due)
	}
	a.watch.observe(spend.Record{Cost: 0.1, KeyID: "k", Status: "success", ModelGroup: "m"})
	if len(a.watch.due()) != 0 {
		t.Fatal("entity re-checked within rate limit")
	}
}

func TestReportEvent(t *testing.T) {
	day := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	tot := analytics.Totals{Requests: 1234, Failures: 12, Cost: 12.5, PromptTokens: 1_000_000, CompletionTokens: 200_000}
	ev := reportEvent(day, tot, []analytics.Row{{Label: "llama", Totals: analytics.Totals{Cost: 10, Requests: 1000}}}, nil, nil)
	if ev.DedupeKey != "daily_report:2026-10-14" || ev.Kind != "daily_report" {
		t.Errorf("unexpected %+v", ev)
	}
	for _, want := range []string{"$12.50", "1,234 requests", "Top models", "• llama — $10.00 · 1,000 requests"} {
		if !strings.Contains(ev.Body, want) {
			t.Errorf("report body missing %q:\n%s", want, ev.Body)
		}
	}
	if ev.Fields["tokens"] != "1.2M" {
		t.Errorf("tokens field = %q", ev.Fields["tokens"])
	}
}

func TestUSD(t *testing.T) {
	for in, want := range map[float64]string{0: "$0.00", 1234567.891: "$1,234,567.89", 0.000123: "$0.000123", 12.5: "$12.50"} {
		if got := USD(in); got != want {
			t.Errorf("USD(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestMattermostPayload(t *testing.T) {
	m := Message{At: time.Unix(1700000000, 0), Event: hooks.Event{Kind: "deployment_down", Severity: "critical",
		Title: "Deployment down: llama", Body: "it broke", Fields: map[string]string{"model": "llama", "api_base": "http://x"}}}
	cfg := ChannelConfig{Mention: "@channel", Channel: "ops-alerts", Username: "Gate", IconURL: "https://x/i.png"}
	p := MattermostPayload(m, cfg)
	s := string(marshal(p))
	for _, want := range []string{`"text":"@channel :rotating_light: Deployment down: llama"`, `"color":"#E5484D"`,
		`"title":"Deployment down: llama"`, `"text":"it broke"`, `"title":"Api base"`, `"value":"http://x"`, `"short":true`,
		`"channel":"ops-alerts"`, `"username":"Gate"`, `"icon_url":"https://x/i.png"`, `deployment_down`} {
		if !strings.Contains(s, want) {
			t.Errorf("mattermost payload missing %s:\n%s", want, s)
		}
	}
	if strings.Contains(s, `"blocks"`) {
		t.Error("Mattermost does not render Slack blocks; payload must use attachments only")
	}
	m.Event.Severity = "warning"
	p = MattermostPayload(m, ChannelConfig{Mention: "@channel"})
	s = string(marshal(p))
	if strings.Contains(s, "@channel") {
		t.Error("mention should only apply to critical alerts")
	}
	if !strings.Contains(s, `"username":"LemonGate"`) || strings.Contains(s, `"channel"`) || strings.Contains(s, `"icon_url"`) {
		t.Errorf("defaults wrong: %s", s)
	}
}

func TestMattermostDeliveryThroughDispatcher(t *testing.T) {
	var body []byte
	var ctype string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		ctype = r.Header.Get("Content-Type")
		w.Write([]byte("ok")) // Mattermost answers 200 "ok"
	}))
	defer srv.Close()
	box, _ := secret.New("k")
	a := New(nil, box, settings.NewStore(nil), configSMTP())
	ch := Channel{Name: "mm", Kind: KindMattermost, Enabled: true, Config: ChannelConfig{URL: srv.URL + "/hooks/abc123"}}
	m := Message{At: time.Now(), Event: hooks.Event{Kind: "test", Severity: "info", Title: "hello from LemonGate"}}
	if err := a.deliver(context.Background(), ch, m); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil || ctype != "application/json" {
		t.Fatalf("bad request: %v %q %s", err, ctype, body)
	}
	if !strings.Contains(got["text"].(string), "hello from LemonGate") {
		t.Errorf("unexpected text %v", got["text"])
	}
	if ch.Target() != "http://"+strings.TrimPrefix(srv.URL, "http://")+"/…c123" {
		t.Errorf("target should redact the hook id: %s", ch.Target())
	}
}

func TestMattermostConfigValidate(t *testing.T) {
	ok := ChannelConfig{URL: "https://chat.example.com/hooks/x", Channel: "ops-alerts", IconURL: "https://e.com/i.png"}
	if err := ok.Validate(KindMattermost); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []ChannelConfig{{}, {URL: "ftp://x"}, {URL: "https://x/h", IconURL: "notaurl"}, {URL: "https://x/h", Channel: "ops alerts"}} {
		if err := bad.Validate(KindMattermost); err == nil {
			t.Errorf("expected error for %+v", bad)
		}
	}
}
