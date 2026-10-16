package limits

import "testing"

func ptr(i int) *int { return &i }

func TestRPMAndParallel(t *testing.T) {
	l := New()
	s := []Subject{{ID: "key:a", Label: "key a", RPM: ptr(2), MaxParallel: ptr(1)}}
	rel, _, err := l.Acquire(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.Acquire(s); err == nil || err.(*LimitError).Kind != "parallel" {
		t.Fatalf("expected parallel limit, got %v", err)
	}
	rel(10)
	rel2, _, err := l.Acquire(s)
	if err != nil {
		t.Fatal(err)
	}
	rel2(0)
	if _, _, err := l.Acquire(s); err == nil || err.(*LimitError).Kind != "rpm" {
		t.Fatalf("expected rpm limit, got %v", err)
	}
}

func TestTPM(t *testing.T) {
	l := New()
	s := []Subject{{ID: "team:x", Label: "team x", TPM: ptr(100)}}
	rel, _, _ := l.Acquire(s)
	rel(150)
	if _, _, err := l.Acquire(s); err == nil || err.(*LimitError).Kind != "tpm" {
		t.Fatalf("expected tpm limit, got %v", err)
	}
}
