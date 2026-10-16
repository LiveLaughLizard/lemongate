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

func TestAllowedModelsFailsClosedOnEmptyGroups(t *testing.T) {
	r := fakeResolver{groups: map[string][]string{}}
	for name, p := range map[string]*Principal{
		"key group":  {Kind: "key", Key: &store.Key{AccessGroups: []string{"deleted"}}},
		"team group": {Kind: "key", Key: &store.Key{}, Team: &store.Team{Models: []string{"group:deleted"}}},
	} {
		got := p.AllowedModels(r)
		if got == nil || len(got) != 0 || p.CanUseModel(r, "anything") {
			t.Errorf("%s: allowed = %#v, want empty non-nil", name, got)
		}
	}
	if (&Principal{Kind: "key", Key: &store.Key{}}).AllowedModels(r) != nil {
		t.Error("key without restrictions should be unrestricted")
	}
}

func TestTeamAdminKeyManagement(t *testing.T) {
	team, uid, other := "t1", "u1", "u2"
	p := &Principal{Kind: "session", Role: RoleMember, User: &store.User{ID: uid},
		Memberships: []store.TeamMember{{TeamID: team, UserID: uid, Role: TeamRoleAdmin}}}
	if !p.CanManageKey(store.Key{Scope: "inference", TeamID: &team, UserID: &other}) {
		t.Error("team admin should manage team inference keys")
	}
	if p.CanManageKey(store.Key{Scope: "admin", TeamID: &team}) || p.CanManageKey(store.Key{Scope: "management", TeamID: &team}) {
		t.Error("team admin must not manage management/admin keys bound to the team")
	}
}

func TestCheckKeyEdit(t *testing.T) {
	team, uid := "t1", "u1"
	member := &Principal{Kind: "session", Role: RoleMember, User: &store.User{ID: uid},
		Memberships: []store.TeamMember{{TeamID: team, UserID: uid, Role: TeamRoleMember}}}
	owned := store.Key{Scope: "inference", UserID: &uid, TeamID: &team, MCPServers: []string{"docs"}, Blocked: true}

	if err := member.CheckKeyEdit(nil, &store.Key{UserID: &uid, MCPServers: []string{"prod-db"}}); err == nil {
		t.Error("member granted an MCP server on create")
	}
	k := owned
	k.MCPServers = []string{"docs", "prod-db"}
	if err := member.CheckKeyEdit(&owned, &k); err == nil {
		t.Error("member added an MCP server on update")
	}
	k = owned
	k.MCPServers = nil
	if err := member.CheckKeyEdit(&owned, &k); err != nil {
		t.Errorf("removing an MCP server should be allowed: %v", err)
	}
	k = owned
	k.TeamID = nil
	if err := member.CheckKeyEdit(&owned, &k); err == nil {
		t.Error("team member detached a key from its team")
	}
	k = owned
	k.Blocked = false
	if err := member.CheckKeyEdit(&owned, &k); err == nil {
		t.Error("owner unblocked a blocked key")
	}
	admin := &Principal{Kind: "master", Role: RoleAdmin}
	if err := admin.CheckKeyEdit(&owned, &k); err != nil {
		t.Errorf("admin edit rejected: %v", err)
	}
}
