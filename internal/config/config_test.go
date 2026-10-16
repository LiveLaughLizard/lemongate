package config

import "testing"

func TestLoadRejectsWeakKeys(t *testing.T) {
	cases := []struct {
		master, secret, dev string
		ok                  bool
	}{
		{"short", "", "", false},
		{"change-me-master-key", "", "", false},
		{"0123456789abcdef0123", "", "", true},
		{"0123456789abcdef0123", "tiny", "", false},
		{"0123456789abcdef0123", "fedcba9876543210fedc", "", true},
		{"change-me", "", "1", true},
	}
	for _, c := range cases {
		t.Setenv("DATABASE_URL", "postgres://x")
		t.Setenv("LEMONGATE_CONFIG", "")
		t.Setenv("LEMONGATE_MASTER_KEY", c.master)
		t.Setenv("LEMONGATE_SECRET_KEY", c.secret)
		t.Setenv("LEMONGATE_DEV", c.dev)
		cfg, err := Load()
		if (err == nil) != c.ok {
			t.Errorf("master=%q secret=%q dev=%q: err=%v, want ok=%v", c.master, c.secret, c.dev, err, c.ok)
		}
		if err == nil && cfg.SecretKeyDerived != (c.secret == "") {
			t.Errorf("master=%q secret=%q: SecretKeyDerived=%v", c.master, c.secret, cfg.SecretKeyDerived)
		}
	}
}
