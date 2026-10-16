package routing

import "testing"

func TestRedactBase(t *testing.T) {
	for in, want := range map[string]string{
		"http://10.0.0.5:8000":                        "http://10.0.0.5:8000",
		"https://vllm.internal/v1/":                   "https://vllm.internal/v1/",
		"https://user:pw@vllm.internal:8443/v1?k=s#f": "https://vllm.internal:8443/v1",
		"http://host/v1?":                             "http://host/v1",
	} {
		if got := RedactBase(in); got != want {
			t.Errorf("RedactBase(%q) = %q, want %q", in, got, want)
		}
	}
}
