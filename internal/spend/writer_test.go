package spend

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestCleanText(t *testing.T) {
	for in, want := range map[string]string{
		"plain":        "plain",
		"a\x00b\x00":   "ab",
		"bad\xffutf8":  "bad�utf8",
		"\x00":         "",
		"ünïcødé\x00!": "ünïcødé!",
	} {
		if got := CleanText(in); got != want {
			t.Errorf("CleanText(%q) = %q, want %q", in, got, want)
		}
	}
	if got := CleanEndUser(strings.Repeat("é", MaxEndUserLen)); len(got) > MaxEndUserLen || !utf8.ValidString(got) {
		t.Errorf("end user not bounded on a rune boundary: %d bytes", len(got))
	}
}

func TestCleanTags(t *testing.T) {
	in := []string{"keep", " keep ", "a\x00", "a", "", "\x00", strings.Repeat("x", 500)}
	for i := 0; i < 100; i++ {
		in = append(in, "t"+strings.Repeat("y", i))
	}
	got := CleanTags(in)
	if len(got) != MaxTags {
		t.Fatalf("len = %d, want %d", len(got), MaxTags)
	}
	if got[0] != "keep" || got[1] != "a" || len(got[2]) != MaxTagLen {
		t.Fatalf("unexpected head %q", got[:3])
	}
	for _, tag := range got {
		if strings.ContainsRune(tag, 0) || tag == "" || len(tag) > MaxTagLen {
			t.Fatalf("bad tag %q", tag)
		}
	}
	if CleanTags(nil) != nil {
		t.Fatal("nil in, nil out")
	}
}

func TestCleanMetadata(t *testing.T) {
	var md map[string]any
	dec := json.NewDecoder(strings.NewReader(`{"k\u0000":"v\u0000","nested":{"list":["\u0000x",{"d\u0000":"e"}]},
		"lit":"\\u0000","big":1e1000000,"small":1e-1000000,"n":42}`))
	dec.UseNumber()
	if err := dec.Decode(&md); err != nil {
		t.Fatal(err)
	}
	out := CleanMetadata(md)
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(strings.ReplaceAll(s, `\\`, ""), `\u0000`) {
		t.Fatalf("NUL survived: %s", s)
	}
	if out["k"] != "v" || out["lit"] != `\u0000` || out["big"] != "1e1000000" || out["small"] != json.Number("0") || out["n"] != json.Number("42") {
		t.Fatalf("unexpected cleaned metadata: %s", s)
	}
	nested := out["nested"].(map[string]any)["list"].([]any)
	if nested[0] != "x" || nested[1].(map[string]any)["d"] != "e" {
		t.Fatalf("nested values not cleaned: %s", s)
	}
	// The input is not modified.
	if _, ok := md["k\x00"]; !ok {
		t.Fatal("input map was mutated")
	}

	huge := CleanMetadata(map[string]any{"x": strings.Repeat("a", MaxMetadataSize)})
	if huge["truncated"] != true || len(huge) != 2 {
		t.Fatalf("oversized metadata kept: %v", len(huge))
	}
}

func TestCleanJSON(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`{"a":"x\u0000y"}`, `{"a":"xy"}`},
		{`{"a\u0000":["\u0000"]}`, `{"a":[""]}`},
		{`{"a":"\ud800"}`, `{"a":"` + "�" + `"}`},
		{`{"a":"<b>","c":"\u0000"}`, `{"a":"<b>","c":""}`},
		{`{"a":"😀"}`, `{"a":"😀"}`},
		{`{"a":"x\u0000`, ``}, // invalid JSON is dropped
	} {
		if got := string(cleanJSON([]byte(tc.in))); got != tc.want {
			t.Errorf("cleanJSON(%s) = %s, want %s", tc.in, got, tc.want)
		}
	}
	// Untouched when there is nothing to clean, including an escaped backslash
	// followed by "u0000", which is not a NUL escape.
	for _, in := range []string{`{"a":"\\u0000"}`, `{"a":"\\\\","b":"A\n"}`, `{"html":"<b>"}`, `[1,2]`} {
		if got := string(cleanJSON([]byte(in))); got != in {
			t.Errorf("cleanJSON(%s) = %s, want it unchanged", in, got)
		}
	}
	if got := string(cleanJSON([]byte(`{"a":"\\\u0000"}`))); got != `{"a":"\\"}` {
		t.Errorf("escaped backslash then NUL escape: got %s", got)
	}
}

func TestSubmitSanitizesAndTracksPending(t *testing.T) {
	w := NewWriter(nil)
	w.Submit(Record{RequestID: "r1", KeyID: "k", EndUser: "eu\x00", Tags: []string{"t\x00", "t"}, Cost: 1.5,
		Error: "boom\x00", Metadata: map[string]any{"m": "\x00"}, RequestBody: []byte(`{"x":"\u0000"}`)})
	if got := w.Pending("tag:t"); got != 1.5 {
		t.Fatalf("pending tag = %v", got)
	}
	if got := w.Pending("end_user:eu"); got != 1.5 {
		t.Fatalf("pending end user = %v", got)
	}
	r := <-w.ch
	if r.EndUser != "eu" || len(r.Tags) != 1 || r.Error != "boom" || r.Metadata["m"] != "" || string(r.RequestBody) != `{"x":""}` {
		t.Fatalf("record not sanitized: %+v", r)
	}
}

func rejecting(bad func(Record) bool, calls *int) func(context.Context, []Record) error {
	return func(_ context.Context, recs []Record) error {
		*calls++
		for _, r := range recs {
			if bad(r) {
				return &pgconn.PgError{Code: "22P05", Message: "unsupported Unicode escape sequence"}
			}
		}
		return nil
	}
}

func TestWriteIsolatesRejectedRecord(t *testing.T) {
	recs := make([]Record, 100)
	for i := range recs {
		recs[i] = Record{RequestID: "ok", Cost: 1}
	}
	recs[37] = Record{RequestID: "bad", Cost: 1, Metadata: map[string]any{"poison": true}}

	// Rejected only because of its metadata: stored without it.
	calls := 0
	w := NewWriter(nil)
	w.flushFn = rejecting(func(r Record) bool { return r.Metadata["poison"] == true }, &calls)
	settled, retry, committed := w.write(recs)
	if len(settled) != 100 || len(retry) != 0 || committed != 100 {
		t.Fatalf("settled=%d retry=%d committed=%d", len(settled), len(retry), committed)
	}
	if calls > 20 {
		t.Fatalf("too many flush attempts: %d", calls)
	}

	// Rejected whatever we do: dropped, the other 99 are still committed.
	w.flushFn = rejecting(func(r Record) bool { return r.RequestID == "bad" }, &calls)
	settled, retry, committed = w.write(recs)
	if len(settled) != 100 || len(retry) != 0 || committed != 99 {
		t.Fatalf("settled=%d retry=%d committed=%d", len(settled), len(retry), committed)
	}
}

func TestWriteRetainsOnTransientError(t *testing.T) {
	w := NewWriter(nil)
	for _, err := range []error{
		&net.OpError{Op: "dial", Err: errors.New("connection refused")},
		&pgconn.PgError{Code: "40P01"},
		context.DeadlineExceeded,
	} {
		w.flushFn = func(context.Context, []Record) error { return err }
		settled, retry, committed := w.write([]Record{{Cost: 1}, {Cost: 2}})
		if len(settled) != 0 || len(retry) != 2 || committed != 0 {
			t.Fatalf("%v: settled=%d retry=%d committed=%d", err, len(settled), len(retry), committed)
		}
	}
}

func TestRunKeepsPendingUntilWritten(t *testing.T) {
	var mu sync.Mutex
	fail := true
	var written []Record
	w := NewWriter(nil)
	w.flushFn = func(_ context.Context, recs []Record) error {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			return &net.OpError{Op: "dial", Err: errors.New("connection refused")}
		}
		written = append(written, recs...)
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()

	w.Submit(Record{RequestID: "a", KeyID: "k", Cost: 2})
	time.Sleep(1500 * time.Millisecond) // at least one failed tick
	if got := w.Pending("key:k"); got != 2 {
		t.Fatalf("pending released before the record was written: %v", got)
	}
	mu.Lock()
	fail = false
	mu.Unlock()
	deadline := time.Now().Add(3 * time.Second)
	for w.Pending("key:k") != 0 {
		if time.Now().After(deadline) {
			t.Fatal("pending never released after a successful write")
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if len(written) != 1 || written[0].RequestID != "a" {
		t.Fatalf("written = %+v", written)
	}
}
