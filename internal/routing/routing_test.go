package routing

import (
	"testing"
	"time"

	"lemongate/internal/settings"
	"lemongate/internal/store"
)

func dep(id string, weight int) *Deployment {
	return &Deployment{Deployment: store.Deployment{ID: id, Name: "m", Weight: weight, Enabled: true}}
}

func TestWeightedChoiceRespectsWeights(t *testing.T) {
	a, b := dep("a", 9), dep("b", 1)
	counts := map[string]int{}
	for i := 0; i < 5000; i++ {
		counts[choose("weighted", []*Deployment{a, b}).ID]++
	}
	if counts["a"] < 4000 || counts["b"] < 200 {
		t.Fatalf("unexpected distribution %v", counts)
	}
}

func TestLeastBusy(t *testing.T) {
	a, b := dep("a", 1), dep("b", 1)
	a.inflight.Store(3)
	if got := choose("least_busy", []*Deployment{a, b}); got.ID != "b" {
		t.Fatalf("got %s", got.ID)
	}
}

func TestCooldownAfterFailures(t *testing.T) {
	d := dep("a", 1)
	rs := settings.Routing{CooldownFailures: 2, CooldownSeconds: 30}
	d.Begin()
	d.End(false, 0, 0, rs)
	if d.CoolingDown() {
		t.Fatal("cooled down too early")
	}
	d.Begin()
	d.End(false, 0, 0, rs)
	if !d.CoolingDown() {
		t.Fatal("expected cooldown")
	}
	d.ClearCooldown()
	if d.CoolingDown() {
		t.Fatal("cooldown not cleared")
	}
}

func TestLatencyEWMA(t *testing.T) {
	d := dep("a", 1)
	rs := settings.Routing{LatencyEWMAAlpha: 0.5}
	d.Begin()
	d.End(true, 100*time.Millisecond, 0, rs)
	d.Begin()
	d.End(true, 300*time.Millisecond, 0, rs)
	if got := d.LatencyMs(); got < 199 || got > 201 {
		t.Fatalf("ewma = %v", got)
	}
}

func TestBases(t *testing.T) {
	if V1Base("http://h:8000") != "http://h:8000/v1" || V1Base("http://h:8000/v1/") != "http://h:8000/v1" {
		t.Fatal("V1Base")
	}
	if RootBase("http://h:8000/v1") != "http://h:8000" {
		t.Fatal("RootBase")
	}
}
