package store

import (
	"context"
	"time"
)

// Extra queries used by the teams, organizations and users console areas.

// ListUsersInOrg lists users assigned to an organization.
func (s *Store) ListUsersInOrg(ctx context.Context, orgID string) ([]User, error) {
	return queryAll[User](ctx, s, `SELECT `+userCols+userFrom+` WHERE u.org_id::text = $1 ORDER BY u.email`, orgID)
}

// PurgeTeam permanently deletes a (soft-deleted) team. Keys keep their rows with team_id cleared.
// PurgeTeam hard-deletes a team and soft-deletes its keys, which would otherwise
// lose the team's restrictions when team_id is nulled.
func (s *Store) PurgeTeam(ctx context.Context, id string) error {
	return s.deleteOwner(ctx, `UPDATE api_keys SET deleted_at=now(), updated_at=now() WHERE team_id=$1 AND deleted_at IS NULL`,
		`DELETE FROM teams WHERE id=$1`, id)
}

// SetUserBlocked toggles a user's blocked flag.
func (s *Store) SetUserBlocked(ctx context.Context, id string, blocked bool) error {
	return exec(ctx, s, `UPDATE users SET blocked=$2, updated_at=now() WHERE id=$1`, id, blocked)
}

// SetTeamBlocked toggles a team's blocked flag.
func (s *Store) SetTeamBlocked(ctx context.Context, id string, blocked bool) error {
	return exec(ctx, s, `UPDATE teams SET blocked=$2, updated_at=now() WHERE id=$1`, id, blocked)
}

// SetOrgBlocked toggles an organization's blocked flag.
func (s *Store) SetOrgBlocked(ctx context.Context, id string, blocked bool) error {
	return exec(ctx, s, `UPDATE organizations SET blocked=$2, updated_at=now() WHERE id=$1`, id, blocked)
}

// UpdateUserName changes only the display name (self-service profile edits).
func (s *Store) UpdateUserName(ctx context.Context, id, name string) error {
	return exec(ctx, s, `UPDATE users SET name=$2, updated_at=now() WHERE id=$1`, id, name)
}

// UserAccessInfo summarizes sign-in state for a user.
type UserAccessInfo struct {
	ActiveSessions int
	PendingInvite  *time.Time // expiry of the newest unused invite
}

func (s *Store) GetUserAccessInfo(ctx context.Context, userID string) UserAccessInfo {
	var info UserAccessInfo
	_ = s.Pool.QueryRow(ctx, `SELECT count(*)::int FROM sessions WHERE user_id::text=$1 AND expires_at > now()`, userID).Scan(&info.ActiveSessions)
	var exp *time.Time
	if err := s.Pool.QueryRow(ctx, `SELECT max(expires_at) FROM invites WHERE user_id::text=$1 AND used_at IS NULL AND expires_at > now()`, userID).Scan(&exp); err == nil {
		info.PendingInvite = exp
	}
	return info
}

// RevokeUserInvites invalidates every outstanding invite for a user.
func (s *Store) RevokeUserInvites(ctx context.Context, userID string) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM invites WHERE user_id::text=$1 AND used_at IS NULL`, userID)
	return err
}

// SetTeamOrg assigns teams to an organization (nil detaches).
func (s *Store) SetTeamOrg(ctx context.Context, teamID string, orgID *string) error {
	return exec(ctx, s, `UPDATE teams SET org_id=$2, updated_at=now() WHERE id=$1`, teamID, orgID)
}
