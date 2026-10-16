package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lemongate/internal/auth"
	"lemongate/internal/limits"
	"lemongate/internal/settings"
	"lemongate/internal/spend"
	"lemongate/internal/store"
)

func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestParseUsage(t *testing.T) {
	for _, tc := range []struct {
		body       string
		ok         bool
		prompt, cp int
	}{
		{`{"usage":{"prompt_tokens":10,"completion_tokens":5}}`, true, 10, 5},
		{`{"object":"response","usage":{"input_tokens":7,"output_tokens":3,"total_tokens":10}}`, true, 7, 3},
		{`{"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":7,"output_tokens":3,"total_tokens":10}}}`, true, 7, 3},
		{`{"type":"response.incomplete","response":{"usage":{"input_tokens":4,"output_tokens":9}}}`, true, 4, 9},
		{`{"type":"response.created","response":{"status":"in_progress","usage":null}}`, false, 0, 0},
		{`{"type":"response.output_text.delta","delta":"hi"}`, false, 0, 0},
		{`{"choices":[{"delta":{"content":"x"}}],"usage":null}`, false, 0, 0},
	} {
		u, ok := parseUsage(decode(t, tc.body))
		if ok != tc.ok || u.prompt != tc.prompt || u.completion != tc.cp {
			t.Errorf("parseUsage(%s) = %+v, %v", tc.body, u, ok)
		}
	}
}

func master(r *http.Request) *http.Request {
	return r.WithContext(auth.WithPrincipal(r.Context(), &auth.Principal{Kind: "master", Role: auth.RoleAdmin}))
}

func TestStreamMustBeBoolean(t *testing.T) {
	g := New(&Gateway{Settings: settings.NewStore(nil)})
	h := g.handle(endpoint{route: "chat/completions", stream: true})
	for _, v := range []string{`"true"`, `1`, `"yes"`, `{}`, `[true]`} {
		rec := httptest.NewRecorder()
		h(rec, master(httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"m","stream":`+v+`}`))))
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), "'stream' must be a boolean") {
			t.Errorf("stream=%s: %d %s", v, rec.Code, rec.Body.String())
		}
	}
}

func TestRequestBodyTooLarge(t *testing.T) {
	g := New(&Gateway{Settings: settings.NewStore(nil)})
	h := g.handle(endpoint{route: "chat/completions", stream: true})
	rec := httptest.NewRecorder()
	body := io.MultiReader(strings.NewReader(`{"model":"m","x":"`), io.LimitReader(filler{}, 40<<20))
	h(rec, master(httptest.NewRequest("POST", "/v1/chat/completions", body)))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
}

type filler struct{}

func (filler) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

func TestTranscriptionBodyCapped(t *testing.T) {
	g := New(&Gateway{Settings: settings.NewStore(nil), Limiter: limits.New(), Spend: spend.NewWriter(nil)})
	g.bc.loaded = time.Now() // budget cache is fresh: no database needed
	const boundary = "xyz"
	body := io.MultiReader(strings.NewReader("--"+boundary+"\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.wav\"\r\n\r\n"),
		io.LimitReader(filler{}, 40<<20), strings.NewReader("\r\n--"+boundary+"--\r\n"))
	req := httptest.NewRequest("POST", "/v1/audio/transcriptions", body)
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	rec := httptest.NewRecorder()
	g.handleTranscription(rec, master(req))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
}

func TestRequestTagsBounded(t *testing.T) {
	var client []any
	for i := 0; i < 100; i++ {
		client = append(client, strings.Repeat("c", i+1)+"\x00")
	}
	p := &auth.Principal{Kind: "key", Key: &store.Key{ID: "k", Tags: []string{"zz-billing", "team-a"}}}
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("x-lemongate-tags", "hdr\x00,"+strings.Repeat("h", 1000))
	tags := requestTags(r, map[string]any{"tags": client, "metadata": map[string]any{"tags": []any{"md"}}}, p)
	if len(tags) != spend.MaxTags {
		t.Fatalf("len = %d", len(tags))
	}
	has := map[string]bool{}
	for _, tg := range tags {
		if strings.ContainsRune(tg, 0) || len(tg) > spend.MaxTagLen {
			t.Fatalf("bad tag %q", tg)
		}
		has[tg] = true
	}
	if !has["zz-billing"] || !has["team-a"] || !has["hdr"] {
		t.Fatalf("key or header tags dropped: %q", tags)
	}
}

func TestEstimateUsage(t *testing.T) {
	payload := decode(t, `{"messages":[{"role":"user","content":[{"type":"text","text":"0123456789abcdef"},
		{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
		{"type":"input_audio","input_audio":{"data":"QUJDRA==","format":"wav"}}]}],"temperature":0.5}`)
	u := estimateUsage(payload, 40, 3)
	// "user" + "text" + 16 + "image_url" + "input_audio" + "wav" = 4+4+16+9+11+3 = 47 bytes
	if u.prompt != 12 || u.completion != 10 {
		t.Fatalf("estimate = %+v", u)
	}
	if u := estimateUsage(map[string]any{"prompt": []any{json.Number("1"), json.Number("2")}}, 0, 5); u.prompt != 2 || u.completion != 5 {
		t.Fatalf("token-id prompt estimate = %+v", u)
	}
}

func TestErrBody(t *testing.T) {
	_, err := io.ReadAll(http.MaxBytesReader(httptest.NewRecorder(), io.NopCloser(strings.NewReader("abcdef")), 3))
	if e := errBody(err); e.Status != 413 {
		t.Fatalf("status %d", e.Status)
	}
	if e := errBody(context.Canceled); e.Status != 400 {
		t.Fatalf("status %d", e.Status)
	}
}
