package spend

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"lemongate/internal/db"
)

func TestIntegrationWriterSurvivesPoisonedRecords(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, dsn)
	if err != nil {
		t.Skipf("database unavailable: %v", err)
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	model := "spendtest-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	t.Cleanup(func() {
		for _, q := range []string{`DELETE FROM request_logs WHERE model = $1`, `DELETE FROM daily_spend WHERE model = $1`,
			`DELETE FROM daily_tag_spend WHERE model = $1`, `DELETE FROM end_users WHERE id LIKE $1 || '%'`} {
			_, _ = pool.Exec(context.Background(), q, model)
		}
	})

	w := NewWriter(pool)
	wctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { w.Run(wctx); close(done) }()
	for i := 0; i < 5; i++ {
		r := Record{RequestID: fmt.Sprintf("%s-%d", model, i), Route: "chat/completions", Model: model, ModelGroup: model,
			Status: "success", PromptTokens: 10, Cost: 0.001, EndUser: model + "-eu", Tags: []string{model}}
		switch i {
		case 1: // NULs everywhere a client can put them
			r.Metadata = map[string]any{"x\x00": "\x00", "nested": []any{"\x00"}}
			r.EndUser = model + "-eu\x00"
			r.Tags = []string{model + "\x00"}
		case 2:
			r.RequestBody = []byte(`{"x":"\u0000","y":"\ud800"}`)
			r.Error = "bad\x00\xff"
		case 3: // valid JSON that jsonb still refuses: stored without payloads
			r.ResponseBody = []byte(`{"n":1e1000000}`)
		}
		w.Submit(r)
	}
	cancel()
	<-done

	var n int
	var cost float64
	if err := pool.QueryRow(ctx, `SELECT count(*), COALESCE(sum(cost), 0) FROM request_logs WHERE model = $1`, model).Scan(&n, &cost); err != nil {
		t.Fatal(err)
	}
	if n != 5 || cost < 0.0049 {
		t.Fatalf("request_logs: %d rows, cost %v; want 5 rows", n, cost)
	}
	var dropped bool
	_ = pool.QueryRow(ctx, `SELECT (metadata->>'payloads_dropped')::bool FROM request_logs WHERE request_id = $1`, model+"-3").Scan(&dropped)
	if !dropped {
		t.Fatal("record 3 should have been stored without its payloads")
	}
	var reqs int64
	_ = pool.QueryRow(ctx, `SELECT COALESCE(sum(requests), 0) FROM daily_tag_spend WHERE model = $1 AND tag = $1`, model).Scan(&reqs)
	if reqs != 5 {
		t.Fatalf("daily_tag_spend requests = %d, want 5 (NUL-stripped tag merged)", reqs)
	}
	var euSpend float64
	_ = pool.QueryRow(ctx, `SELECT spend FROM end_users WHERE id = $1`, model+"-eu").Scan(&euSpend)
	if euSpend < 0.0049 {
		t.Fatalf("end user spend = %v", euSpend)
	}
	if p := w.Pending("end_user:" + model + "-eu"); p != 0 {
		t.Fatalf("pending not released: %v", p)
	}
}
