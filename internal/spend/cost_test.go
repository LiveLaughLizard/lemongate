package spend

import "testing"

func TestCost(t *testing.T) {
	got := Cost(1_000_000, 500_000, 0.5, 1.5)
	if got != 1.25 {
		t.Fatalf("cost = %v, want 1.25", got)
	}
}
