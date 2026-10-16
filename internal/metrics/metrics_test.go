package metrics

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// liveNames are emitted by the scrape-time collector in package app.
var liveNames = map[string]bool{DeploymentInFlightName: true, DeploymentHealthyName: true, DeploymentCoolingName: true,
	DeploymentLatencyName: true, DeploymentsName: true, CacheEntriesName: true, CacheBytesName: true, SpendQueueName: true}

func catalogNames() map[string]Info {
	out := map[string]Info{}
	for _, m := range Catalog {
		out[m.Name] = m
	}
	return out
}

func TestCatalogMatchesRegistry(t *testing.T) {
	// Touch every vec so it shows up in Gather.
	BuildInfo.WithLabelValues("t", "go").Set(1)
	Requests.WithLabelValues("r", "m", "success").Add(0)
	Tokens.WithLabelValues("m", "prompt").Add(0)
	Cost.WithLabelValues("m").Add(0)
	Latency.WithLabelValues("r", "m").Observe(0)
	TTFT.WithLabelValues("m").Observe(0)
	UpstreamRequests.WithLabelValues("m", "b", "d", "2xx").Add(0)
	UpstreamLatency.WithLabelValues("m", "b", "d").Observe(0)
	DeploymentFailures.WithLabelValues("m", "b", "d").Add(0)
	Retries.WithLabelValues("m").Add(0)
	Fallbacks.WithLabelValues("a", "b", "general").Add(0)
	RateLimited.WithLabelValues("rpm").Add(0)
	CacheLookups.WithLabelValues("hit").Add(0)
	GuardrailActions.WithLabelValues("g", "blocked").Add(0)
	MCPCalls.WithLabelValues("s", "ok").Add(0)
	AlertsSent.WithLabelValues("slack", "ok").Add(0)

	fams, err := Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	cat := catalogNames()
	seen := map[string]bool{}
	for _, f := range fams {
		name := f.GetName()
		if !strings.HasPrefix(name, "lemongate_") {
			continue
		}
		seen[name] = true
		info, ok := cat[name]
		if !ok {
			t.Errorf("%s is exported but missing from Catalog", name)
			continue
		}
		if got := strings.ToLower(f.GetType().String()); got != info.Type {
			t.Errorf("%s: catalog type %s, registry type %s", name, info.Type, got)
		}
	}
	for _, m := range Catalog {
		if !seen[m.Name] && !liveNames[m.Name] && !m.Optional {
			t.Errorf("catalog lists %s but the registry does not export it", m.Name)
		}
	}
}

func TestGrafanaDashboardReferencesKnownMetrics(t *testing.T) {
	raw := GrafanaDashboard("Test")
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("dashboard is not valid JSON: %v", err)
	}
	if doc["title"] != "Test" {
		t.Fatalf("title = %v", doc["title"])
	}
	panels := doc["panels"].([]any)
	if len(panels) < 20 {
		t.Fatalf("only %d panels", len(panels))
	}
	cat := catalogNames()
	re := regexp.MustCompile(`lemongate_[a-z0-9_]+`)
	ids := map[float64]bool{}
	for _, p := range panels {
		pm := p.(map[string]any)
		id := pm["id"].(float64)
		if ids[id] {
			t.Errorf("duplicate panel id %v", id)
		}
		ids[id] = true
		pos := pm["gridPos"].(map[string]any)
		if x, w := pos["x"].(float64), pos["w"].(float64); x+w > 24 {
			t.Errorf("panel %q overflows the grid", pm["title"])
		}
		ts, _ := pm["targets"].([]any)
		for _, tg := range ts {
			expr := tg.(map[string]any)["expr"].(string)
			for _, name := range re.FindAllString(expr, -1) {
				base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(name, "_bucket"), "_sum"), "_count")
				if _, ok := cat[base]; !ok {
					t.Errorf("panel %q queries unknown metric %s", pm["title"], name)
				}
			}
		}
	}
}

func TestCodeClass(t *testing.T) {
	for in, want := range map[int]string{0: "error", 200: "2xx", 302: "3xx", 404: "4xx", 429: "4xx", 503: "5xx"} {
		if got := CodeClass(in); got != want {
			t.Errorf("CodeClass(%d) = %s, want %s", in, got, want)
		}
	}
}
