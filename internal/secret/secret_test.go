package secret

import "testing"

func TestHint(t *testing.T) {
	for in, want := range map[string]string{
		"":                  "••••",
		"short":             "••••",
		"0123456789abcde":   "••••",
		"0123456789abcdef":  "…cdef",
		"sk-0123456789a1b2": "…a1b2",
	} {
		if got := Hint(in); got != want {
			t.Errorf("Hint(%q) = %q, want %q", in, got, want)
		}
	}
}
