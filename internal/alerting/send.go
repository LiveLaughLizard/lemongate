package alerting

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"lemongate/internal/hooks"
)

// Message is an event at a point in time, ready to be formatted.
type Message struct {
	Event hooks.Event
	At    time.Time
}

// Body returns the event body, falling back to the title.
func (m Message) Body() string {
	if m.Event.Body != "" {
		return m.Event.Body
	}
	return m.Event.Title
}

// SortedFields returns field keys in a stable order.
func (m Message) SortedFields() []string {
	keys := make([]string, 0, len(m.Event.Fields))
	for k := range m.Event.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// FieldLabel turns "api_base" into "Api base".
func FieldLabel(k string) string {
	k = strings.ReplaceAll(k, "_", " ")
	if k == "" {
		return k
	}
	return strings.ToUpper(k[:1]) + k[1:]
}

// Presentation per severity.
type severityStyle struct {
	Emoji string // Slack shortcode
	Color string // hex
	Label string
}

func styleFor(sev string) severityStyle {
	switch sev {
	case "critical":
		return severityStyle{":rotating_light:", "#E5484D", "Critical"}
	case "warning":
		return severityStyle{":warning:", "#F5A524", "Warning"}
	}
	return severityStyle{":information_source:", "#3B82F6", "Info"}
}

// --- Slack ---

// SlackPayload builds an incoming-webhook payload: a colored attachment with
// header, body, fields and a context line.
func SlackPayload(m Message, mention string) map[string]any {
	st := styleFor(m.Event.Severity)
	title := st.Emoji + " " + m.Event.Title
	blocks := []any{
		map[string]any{"type": "header", "text": map[string]any{"type": "plain_text", "text": truncate(title, 150), "emoji": true}},
	}
	body := m.Body()
	if mention != "" && m.Event.Severity == "critical" {
		body = mention + " " + body
	}
	if body != "" && body != m.Event.Title {
		blocks = append(blocks, map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": truncate(body, 2900)}})
	}
	var fields []any
	for _, k := range m.SortedFields() {
		if len(fields) == 10 { // Slack limit per section
			break
		}
		fields = append(fields, map[string]any{"type": "mrkdwn", "text": truncate("*"+FieldLabel(k)+"*\n"+m.Event.Fields[k], 1900)})
	}
	if len(fields) > 0 {
		blocks = append(blocks, map[string]any{"type": "section", "fields": fields})
	}
	blocks = append(blocks, map[string]any{"type": "context", "elements": []any{
		map[string]any{"type": "mrkdwn", "text": fmt.Sprintf("*%s* · `%s` · LemonGate · <!date^%d^{date_short_pretty} {time}|%s>",
			st.Label, m.Event.Kind, m.At.Unix(), m.At.UTC().Format(time.RFC1123))},
	}})
	return map[string]any{
		"text":        title, // notification fallback
		"attachments": []any{map[string]any{"color": st.Color, "blocks": blocks}},
	}
}

func (a *Alerter) sendSlack(ctx context.Context, cfg ChannelConfig, m Message) error {
	return a.post(ctx, cfg.URL, marshal(SlackPayload(m, cfg.Mention)), nil)
}

// --- Mattermost ---

// MattermostPayload builds an incoming-webhook payload. Mattermost renders Markdown
// and message attachments (color bar, title, fields, footer) but not block layouts.
func MattermostPayload(m Message, cfg ChannelConfig) map[string]any {
	st := styleFor(m.Event.Severity)
	title := st.Emoji + " " + m.Event.Title
	text := m.Body()
	if text == m.Event.Title {
		text = ""
	}
	var fields []any
	for _, k := range m.SortedFields() {
		v := m.Event.Fields[k]
		fields = append(fields, map[string]any{"title": FieldLabel(k), "value": truncate(v, 1000), "short": len(v) <= 40})
	}
	att := map[string]any{
		"fallback": title,
		"color":    st.Color,
		"title":    truncate(m.Event.Title, 250),
		"text":     truncate(text, 3500),
		"fields":   fields,
		"footer":   fmt.Sprintf("%s · %s · LemonGate · %s", st.Label, m.Event.Kind, m.At.UTC().Format("2006-01-02 15:04 MST")),
	}
	if fields == nil {
		att["fields"] = []any{}
	}
	out := map[string]any{"attachments": []any{att}}
	// The top-level text drives notifications; mentions only notify from there.
	if cfg.Mention != "" && m.Event.Severity == "critical" {
		out["text"] = cfg.Mention + " " + title
	} else {
		out["text"] = title
	}
	username := cfg.Username
	if username == "" {
		username = "LemonGate"
	}
	out["username"] = username
	if cfg.IconURL != "" {
		out["icon_url"] = cfg.IconURL
	}
	if cfg.Channel != "" {
		out["channel"] = cfg.Channel
	}
	return out
}

func (a *Alerter) sendMattermost(ctx context.Context, cfg ChannelConfig, m Message) error {
	return a.post(ctx, cfg.URL, marshal(MattermostPayload(m, cfg)), nil)
}

// --- generic webhook ---

// WebhookPayload is the JSON document POSTed to webhook channels.
type WebhookPayload struct {
	Event     string            `json:"event"`
	Severity  string            `json:"severity"`
	Title     string            `json:"title"`
	Body      string            `json:"body"`
	Fields    map[string]string `json:"fields"`
	Timestamp string            `json:"timestamp"`
	DedupeKey string            `json:"dedupe_key,omitempty"`
}

func NewWebhookPayload(m Message) WebhookPayload {
	f := m.Event.Fields
	if f == nil {
		f = map[string]string{}
	}
	return WebhookPayload{Event: m.Event.Kind, Severity: m.Event.Severity, Title: m.Event.Title, Body: m.Body(),
		Fields: f, Timestamp: m.At.UTC().Format(time.RFC3339), DedupeKey: m.Event.DedupeKey}
}

// SignatureHeader carries "sha256=<hex>" where hex = HMAC-SHA256(secret, timestamp + "." + body).
// TimestampHeader carries the unix timestamp used in the signature (replay protection).
const (
	SignatureHeader = "X-LemonGate-Signature"
	TimestampHeader = "X-LemonGate-Timestamp"
)

// Sign computes the webhook signature header value.
func Sign(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature checks a signature produced by Sign (for receivers and tests).
func VerifySignature(secret, timestamp string, body []byte, sig string) bool {
	return hmac.Equal([]byte(Sign(secret, timestamp, body)), []byte(sig))
}

func (a *Alerter) sendWebhook(ctx context.Context, cfg ChannelConfig, m Message) error {
	b := marshal(NewWebhookPayload(m))
	h := http.Header{}
	for k, v := range cfg.Headers {
		h.Set(k, v)
	}
	ts := strconv.FormatInt(m.At.Unix(), 10)
	h.Set(TimestampHeader, ts)
	h.Set("X-LemonGate-Event", m.Event.Kind)
	if cfg.Secret != "" {
		h.Set(SignatureHeader, Sign(cfg.Secret, ts, b))
	}
	return a.post(ctx, cfg.URL, b, h)
}

func (a *Alerter) post(ctx context.Context, target string, body []byte, h http.Header) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return redactURLError(err)
	}
	for k, v := range h {
		req.Header[k] = v
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "LemonGate-Alerts/1")
	resp, err := a.client.Do(req)
	if err != nil {
		return redactURLError(err)
	}
	defer resp.Body.Close()
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := strings.TrimSpace(string(snippet))
		if msg != "" {
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(msg, 200))
		}
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// redactURLError cuts the URL quoted by a *url.Error down to scheme and host.
// Incoming-webhook URLs carry their secret in the path (Slack, Mattermost), and
// delivery errors are stored in alert history, logged and shown in the console.
func redactURLError(err error) error {
	var ue *url.Error
	if !errors.As(err, &ue) {
		return err
	}
	origin := "…"
	if u, perr := url.Parse(ue.URL); perr == nil && u.Host != "" {
		origin = u.Scheme + "://" + u.Host + "/…"
	}
	return &url.Error{Op: ue.Op, URL: origin, Err: ue.Err}
}

// --- email ---

// EmailSubject is "[LemonGate] [CRITICAL] title" (severity tag omitted for info).
func EmailSubject(m Message) string {
	s := "[LemonGate] "
	if m.Event.Severity != "info" && m.Event.Severity != "" {
		s += "[" + strings.ToUpper(m.Event.Severity) + "] "
	}
	return s + m.Event.Title
}

// EmailText renders the plain-text body.
func EmailText(m Message) string {
	var b strings.Builder
	b.WriteString(m.Event.Title + "\n")
	b.WriteString(strings.Repeat("=", min(len(m.Event.Title), 72)) + "\n\n")
	if body := m.Body(); body != m.Event.Title {
		b.WriteString(body + "\n\n")
	}
	for _, k := range m.SortedFields() {
		fmt.Fprintf(&b, "%s: %s\n", FieldLabel(k), m.Event.Fields[k])
	}
	fmt.Fprintf(&b, "\nSeverity: %s · Event: %s · %s\n-- \nSent by LemonGate alerting\n", m.Event.Severity, m.Event.Kind,
		m.At.UTC().Format("2006-01-02 15:04 MST"))
	return b.String()
}

// EmailHTML renders a simple, inline-styled HTML body that survives mail clients.
func EmailHTML(m Message) string {
	st := styleFor(m.Event.Severity)
	esc := html.EscapeString
	var b strings.Builder
	b.WriteString(`<!doctype html><html><body style="margin:0;padding:24px;background:#f6f7f2;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1f2420">`)
	b.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:640px;margin:0 auto;background:#ffffff;border-radius:14px;border:1px solid #e4e7dc;overflow:hidden">`)
	fmt.Fprintf(&b, `<tr><td style="height:6px;background:%s"></td></tr>`, st.Color)
	b.WriteString(`<tr><td style="padding:24px 28px">`)
	fmt.Fprintf(&b, `<div style="display:inline-block;padding:2px 10px;border-radius:999px;background:%s1a;color:%s;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.04em">%s</div>`,
		st.Color, st.Color, esc(st.Label))
	fmt.Fprintf(&b, `<h1 style="margin:12px 0 8px;font-size:20px;line-height:1.3">%s</h1>`, esc(m.Event.Title))
	if body := m.Body(); body != m.Event.Title {
		fmt.Fprintf(&b, `<p style="margin:0 0 16px;font-size:14px;line-height:1.6;white-space:pre-line">%s</p>`, esc(body))
	}
	if keys := m.SortedFields(); len(keys) > 0 {
		b.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;font-size:13px">`)
		for _, k := range keys {
			fmt.Fprintf(&b, `<tr><td style="padding:8px 12px 8px 0;border-top:1px solid #eef0e8;color:#6b7266;width:35%%;vertical-align:top">%s</td><td style="padding:8px 0;border-top:1px solid #eef0e8;font-family:ui-monospace,Menlo,monospace;word-break:break-all">%s</td></tr>`,
				esc(FieldLabel(k)), esc(m.Event.Fields[k]))
		}
		b.WriteString(`</table>`)
	}
	fmt.Fprintf(&b, `<p style="margin:20px 0 0;font-size:12px;color:#8a9184">%s · %s · LemonGate alerting</p>`,
		esc(m.Event.Kind), esc(m.At.UTC().Format("2006-01-02 15:04 MST")))
	b.WriteString(`</td></tr></table></body></html>`)
	return b.String()
}

// BuildEmail assembles a multipart/alternative RFC 5322 message.
func BuildEmail(from string, to []string, m Message) []byte {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	hdr := func(k, v string) { fmt.Fprintf(&buf, "%s: %s\r\n", k, v) }
	hdr("From", from)
	hdr("To", strings.Join(to, ", "))
	hdr("Subject", mime.QEncoding.Encode("utf-8", EmailSubject(m)))
	hdr("Date", m.At.Format(time.RFC1123Z))
	hdr("Message-ID", "<"+randomID()+"@lemongate>")
	hdr("MIME-Version", "1.0")
	hdr("X-LemonGate-Event", m.Event.Kind)
	hdr("Content-Type", "multipart/alternative; boundary="+mw.Boundary())
	buf.WriteString("\r\n")
	part := func(ctype, content string) {
		w, _ := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {ctype + "; charset=utf-8"}, "Content-Transfer-Encoding": {"quoted-printable"}})
		qp := quotedprintable.NewWriter(w)
		_, _ = qp.Write([]byte(content))
		_ = qp.Close()
	}
	part("text/plain", EmailText(m))
	part("text/html", EmailHTML(m))
	_ = mw.Close()
	return buf.Bytes()
}

func randomID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ErrSMTPDisabled is returned when an email channel fires without SMTP settings.
var ErrSMTPDisabled = errors.New("SMTP is not configured (set LEMONGATE_SMTP_HOST and LEMONGATE_SMTP_FROM)")

func (a *Alerter) sendEmail(ctx context.Context, cfg ChannelConfig, m Message) error {
	if !a.smtp.Enabled() {
		return ErrSMTPDisabled
	}
	port := a.smtp.Port
	if port == 0 {
		port = 587
	}
	addr := net.JoinHostPort(a.smtp.Host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	var err error
	tlsCfg := &tls.Config{ServerName: a.smtp.Host, MinVersion: tls.VersionTLS12}
	if port == 465 { // implicit TLS
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("connect %s: %w", addr, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	c, err := smtp.NewClient(conn, a.smtp.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if port != 465 {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsCfg); err != nil {
				return fmt.Errorf("starttls: %w", err)
			}
		} else if a.smtp.StartTLS {
			return errors.New("server does not support STARTTLS (set LEMONGATE_SMTP_STARTTLS=0 to allow plaintext)")
		}
	}
	if a.smtp.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", a.smtp.Username, a.smtp.Password, a.smtp.Host)); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	from := a.smtp.From
	if addr, err := parseAddr(from); err == nil {
		from = addr
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, r := range cfg.Recipients {
		if err := c.Rcpt(r); err != nil {
			return fmt.Errorf("recipient %s: %w", r, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(BuildEmail(a.smtp.From, cfg.Recipients, m)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func parseAddr(s string) (string, error) {
	a, err := mail.ParseAddress(s)
	if err != nil {
		return "", err
	}
	return a.Address, nil
}

// marshal encodes JSON without HTML escaping (payloads are not embedded in HTML).
func marshal(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return bytes.TrimRight(buf.Bytes(), "\n")
}
