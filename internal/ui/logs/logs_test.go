package logs

import (
	"net/http/httptest"
	"strings"
	"testing"

	"lemongate/internal/analytics"
	"lemongate/internal/auth"
	"lemongate/internal/ui"
	"lemongate/web"
)

func TestOwnsLog(t *testing.T) {
	me, other, myKey, teamKey := "u1", "u2", "k1", "k2"
	for _, c := range []struct {
		l    analytics.LogEntry
		uid  string
		want bool
	}{
		{analytics.LogEntry{UserID: &me}, me, true},
		{analytics.LogEntry{KeyID: &myKey}, me, true},
		{analytics.LogEntry{UserID: &other, KeyID: &teamKey}, me, false},
		{analytics.LogEntry{KeyID: &teamKey}, me, false},
		{analytics.LogEntry{}, "", false},
	} {
		if got := ownsLog(c.l, c.uid, []string{myKey}); got != c.want {
			t.Errorf("ownsLog(%+v, %q) = %v", c.l, c.uid, got)
		}
	}
}

func TestLogDetailHidesPayload(t *testing.T) {
	r := ui.NewRenderer(web.FS(""), false)
	body := []byte(`{"messages":[{"role":"user","content":"teammate secret prompt"}]}`)
	render := func(sd showData) string {
		rr := httptest.NewRecorder()
		r.Exec(rr, 200, area, "log-detail", ui.Page{P: &auth.Principal{Role: auth.RoleMember}, Data: sd})
		if rr.Code != 200 {
			t.Fatalf("render: %d %s", rr.Code, rr.Body.String())
		}
		return rr.Body.String()
	}
	out := render(showData{L: analytics.LogEntry{Status: "success", RequestBody: body}})
	if !strings.Contains(out, "teammate secret prompt") {
		t.Fatal("visible payload not rendered")
	}
	out = render(showData{L: analytics.LogEntry{Status: "success"}, PayloadHidden: true})
	if !strings.Contains(out, "Payloads are hidden") || strings.Contains(out, "No payloads stored") {
		t.Fatal("hidden-payload note missing")
	}
}
