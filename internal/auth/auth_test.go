package auth

import (
	"testing"

	"lemongate/internal/store"
)

type fakeResolver struct{ groups map[string][]string }

func (f fakeResolver) ExpandAccessGroups(names []string) []string {
	var out []string
	for _, n := range names {
		out = append(out, f.groups[n]...)
	}
	return out
}
func (f fakeResolver) AllModelNames() []string { return nil }

func TestAllowedModelsIntersects(t *testing.T) {
	r := fakeResolver{groups: map[string][]string{"g": {"b", "c"}}}
	team := &store.Team{Models: []string{"a", "b", "c"}}
	key := &store.Key{AccessGroups: []string{"g"}}
	p := &Principal{Kind: "key", Key: key, Team: team}
	got := p.AllowedModels(r)
	if len(got) != 2 || !p.CanUseModel(r, "b") || p.CanUseModel(r, "a") {
		t.Fatalf("allowed = %v", got)
	}
	p.Key = &store.Key{}
	if !p.CanUseModel(r, "a") || p.CanUseModel(r, "z") {
		t.Fatal("team restriction not applied")
	}
	if (&Principal{Kind: "master"}).AllowedModels(r) != nil {
		t.Fatal("master should be unrestricted")
	}
}

func TestKeyFormat(t *testing.T) {
	plain, hash, hint := NewKey()
	if len(plain) != 43 || HashToken(plain) != hash || hint[:3] != "lg-" {
		t.Fatalf("%s %s %s", plain, hash, hint)
	}
}
