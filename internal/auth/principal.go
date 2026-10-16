package auth

import (
	"errors"
	"slices"

	"lemongate/internal/store"
)

// Application roles.
const (
	RoleAdmin        = "admin"
	RoleAdminViewer  = "admin_viewer"
	RoleMember       = "member"
	RoleMemberViewer = "member_viewer"

	TeamRoleAdmin  = "team_admin"
	TeamRoleMember = "team_member"
)

var Roles = []string{RoleAdmin, RoleAdminViewer, RoleMember, RoleMemberViewer}

func RoleLabel(r string) string {
	switch r {
	case RoleAdmin:
		return "Admin"
	case RoleAdminViewer:
		return "Admin (read-only)"
	case RoleMember:
		return "Member"
	case RoleMemberViewer:
		return "Member (read-only)"
	case TeamRoleAdmin:
		return "Team admin"
	case TeamRoleMember:
		return "Team member"
	}
	return r
}

// Principal is an authenticated caller.
type Principal struct {
	Kind string // master | key | session
	Role string // effective application role

	Key  *store.Key
	User *store.User
	Team *store.Team
	Org  *store.Organization

	// Team memberships (session principals only, loaded lazily by the UI layer).
	Memberships []store.TeamMember

	SessionCSRF string
}

func (p *Principal) IsAdmin() bool { return p != nil && p.Role == RoleAdmin }

// CanViewAll reports read access to every entity.
func (p *Principal) CanViewAll() bool {
	return p != nil && (p.Role == RoleAdmin || p.Role == RoleAdminViewer)
}

func (p *Principal) ReadOnly() bool {
	return p == nil || p.Role == RoleAdminViewer || p.Role == RoleMemberViewer
}

func (p *Principal) UserID() string {
	if p != nil && p.User != nil {
		return p.User.ID
	}
	return ""
}

func (p *Principal) KeyID() string {
	if p != nil && p.Key != nil {
		return p.Key.ID
	}
	return ""
}

func (p *Principal) TeamID() string {
	if p != nil && p.Team != nil {
		return p.Team.ID
	}
	return ""
}

func (p *Principal) OrgID() string {
	if p != nil && p.Org != nil {
		return p.Org.ID
	}
	return ""
}

// Label is a human readable actor name for audit entries.
func (p *Principal) Label() string {
	switch {
	case p == nil:
		return "anonymous"
	case p.Kind == "master", p.User == nil && p.Key == nil && p.Role == RoleAdmin:
		return "master key"
	case p.User != nil:
		return p.User.Email
	case p.Key != nil:
		return "key " + p.Key.Label()
	}
	return p.Kind
}

// IsTeamAdmin reports whether the principal administers the given team.
func (p *Principal) IsTeamAdmin(teamID string) bool {
	if p.IsAdmin() {
		return true
	}
	for _, m := range p.Memberships {
		if m.TeamID == teamID && m.Role == TeamRoleAdmin {
			return true
		}
	}
	return false
}

func (p *Principal) InTeam(teamID string) bool {
	for _, m := range p.Memberships {
		if m.TeamID == teamID {
			return true
		}
	}
	return false
}

// CanManageKey reports whether the principal may edit/delete the key.
func (p *Principal) CanManageKey(k store.Key) bool {
	if p.IsAdmin() {
		return true
	}
	if p.ReadOnly() {
		return false
	}
	if k.UserID != nil && *k.UserID == p.UserID() {
		return true
	}
	// Team admins manage their team's inference keys only: management and admin keys
	// bound to a team would otherwise let them regenerate an admin credential.
	return k.TeamID != nil && k.Scope == "inference" && p.IsTeamAdmin(*k.TeamID)
}

// CheckKeyEdit enforces what a non-admin may change when creating (before == nil) or
// updating a key; the console and the API both call it after binding input onto k.
func (p *Principal) CheckKeyEdit(before, k *store.Key) error {
	if p.IsAdmin() {
		return nil
	}
	var old store.Key
	if before != nil {
		old = *before
	}
	for _, s := range k.MCPServers {
		if !slices.Contains(old.MCPServers, s) {
			return errors.New("only admins can grant MCP servers on a key")
		}
	}
	if old.TeamID != nil && store.Deref(k.TeamID) != *old.TeamID && !p.IsTeamAdmin(*old.TeamID) {
		return errors.New("only an admin of the key's team can move it out of the team")
	}
	if k.TeamID != nil && store.Deref(old.TeamID) != *k.TeamID && !p.IsTeamAdmin(*k.TeamID) {
		return errors.New("you can only assign keys to teams you administer")
	}
	if old.Blocked && !k.Blocked && !p.CanUnblockKey(old) {
		return errors.New("only an admin can unblock this key")
	}
	return nil
}

// CanUnblockKey reports whether the principal may lift a block on k. Owners can block
// their own keys but not undo a block placed by an admin or team admin.
func (p *Principal) CanUnblockKey(k store.Key) bool {
	return p.IsAdmin() || (!p.ReadOnly() && k.TeamID != nil && k.Scope == "inference" && p.IsTeamAdmin(*k.TeamID))
}

func (p *Principal) CanViewKey(k store.Key) bool {
	if p.CanViewAll() || p.CanManageKey(k) {
		return true
	}
	if k.UserID != nil && *k.UserID == p.UserID() {
		return true
	}
	return k.TeamID != nil && p.InTeam(*k.TeamID)
}

// ModelResolver expands access-group names into model names.
type ModelResolver interface {
	ExpandAccessGroups(names []string) []string
	AllModelNames() []string
}

// AllowedModels returns the model names the principal may call, or nil meaning
// "every model". Restrictions intersect from org → team → user → key.
func (p *Principal) AllowedModels(r ModelResolver) []string {
	if p == nil || p.Kind == "master" || (p.Kind == "session" && p.IsAdmin()) {
		return nil
	}
	var allowed []string // nil = unrestricted
	// restrict intersects with a configured list. An empty list means "no restriction",
	// but a non-empty one that expands to nothing (e.g. a deleted access group) allows
	// nothing rather than everything.
	restrict := func(list []string) {
		if len(list) == 0 {
			return
		}
		list = expand(list, r)
		if slices.Contains(list, "*") {
			return
		}
		if allowed == nil {
			allowed = append([]string{}, list...) // non-nil even when list is empty
			return
		}
		allowed = slices.DeleteFunc(allowed, func(m string) bool { return !slices.Contains(list, m) })
		if allowed == nil {
			allowed = []string{}
		}
	}
	if p.Org != nil {
		restrict(p.Org.Models)
	}
	if p.Team != nil {
		restrict(p.Team.Models)
	} else if p.User != nil {
		restrict(p.User.Models)
	}
	if p.Key != nil {
		keyList := slices.Clone(p.Key.Models)
		for _, g := range p.Key.AccessGroups {
			keyList = append(keyList, "group:"+g)
		}
		restrict(keyList)
	}
	if allowed != nil {
		slices.Sort(allowed)
		allowed = slices.Compact(allowed)
	}
	return allowed
}

func expand(list []string, r ModelResolver) []string {
	var out []string
	for _, m := range list {
		if len(m) > 6 && m[:6] == "group:" {
			out = append(out, r.ExpandAccessGroups([]string{m[6:]})...)
			continue
		}
		out = append(out, m)
	}
	return out
}

// CanUseModel checks a single (alias-resolved) model group name.
func (p *Principal) CanUseModel(r ModelResolver, model string) bool {
	allowed := p.AllowedModels(r)
	return allowed == nil || slices.Contains(allowed, model)
}
