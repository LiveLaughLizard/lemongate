package store

import (
	"context"
	"time"
)

const teamCols = `t.id, t.name, t.description, t.org_id, t.models, t.max_budget, t.budget_period, t.budget_reset_at, t.spend,
	t.member_max_budget, t.rpm_limit, t.tpm_limit, t.max_parallel, t.guardrails, t.policies, t.mcp_servers, t.metadata, t.blocked,
	t.created_at, t.updated_at, t.deleted_at,
	(SELECT count(*) FROM team_members m WHERE m.team_id = t.id)::int AS member_count,
	(SELECT count(*) FROM api_keys k WHERE k.team_id = t.id AND k.deleted_at IS NULL)::int AS key_count,
	o.name AS org_name`

const teamFrom = ` FROM teams t LEFT JOIN organizations o ON o.id = t.org_id`

func (s *Store) ListTeams(ctx context.Context, search, orgID string) ([]Team, error) {
	return queryAll[Team](ctx, s, `SELECT `+teamCols+teamFrom+` WHERE t.deleted_at IS NULL AND ($1 = '' OR t.name ILIKE '%'||$1||'%')
		AND ($2 = '' OR t.org_id::text = $2) ORDER BY t.name`, search, orgID)
}

func (s *Store) ListDeletedTeams(ctx context.Context) ([]Team, error) {
	return queryAll[Team](ctx, s, `SELECT `+teamCols+teamFrom+` WHERE t.deleted_at IS NOT NULL ORDER BY t.deleted_at DESC`)
}

// TeamsForUser lists teams the user belongs to.
func (s *Store) TeamsForUser(ctx context.Context, userID string) ([]Team, error) {
	return queryAll[Team](ctx, s, `SELECT `+teamCols+teamFrom+` JOIN team_members tm ON tm.team_id = t.id AND tm.user_id::text = $1
		WHERE t.deleted_at IS NULL ORDER BY t.name`, userID)
}

func (s *Store) GetTeam(ctx context.Context, id string) (Team, error) {
	return queryOne[Team](ctx, s, `SELECT `+teamCols+teamFrom+` WHERE t.id::text = $1`, id)
}

func (s *Store) GetTeamByName(ctx context.Context, name string) (Team, error) {
	return queryOne[Team](ctx, s, `SELECT `+teamCols+teamFrom+` WHERE t.name = $1 AND t.deleted_at IS NULL`, name)
}

func (s *Store) CreateTeam(ctx context.Context, t Team) (Team, error) {
	if t.Metadata == nil {
		t.Metadata = map[string]any{}
	}
	var id string
	err := s.Pool.QueryRow(ctx, `INSERT INTO teams (name, description, org_id, models, max_budget, budget_period, budget_reset_at,
		member_max_budget, rpm_limit, tpm_limit, max_parallel, guardrails, mcp_servers, metadata, blocked, policies)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING id`,
		t.Name, t.Description, t.OrgID, CleanList(t.Models), t.MaxBudget, t.BudgetPeriod, NextReset(t.BudgetPeriod, time.Now()),
		t.MemberMaxBudget, t.RPMLimit, t.TPMLimit, t.MaxParallel, CleanList(t.Guardrails), CleanList(t.MCPServers), t.Metadata, t.Blocked, CleanList(t.Policies)).Scan(&id)
	if err != nil {
		return Team{}, mapErr(err)
	}
	return s.GetTeam(ctx, id)
}

func (s *Store) UpdateTeam(ctx context.Context, t Team) error {
	if t.Metadata == nil {
		t.Metadata = map[string]any{}
	}
	return exec(ctx, s, `UPDATE teams SET name=$2, description=$3, org_id=$4, models=$5, max_budget=$6, budget_period=$7,
		budget_reset_at = CASE WHEN budget_period IS DISTINCT FROM $7 THEN $8 ELSE budget_reset_at END,
		member_max_budget=$9, rpm_limit=$10, tpm_limit=$11, max_parallel=$12, guardrails=$13, mcp_servers=$14, metadata=$15,
		blocked=$16, policies=$17, updated_at=now() WHERE id=$1`,
		t.ID, t.Name, t.Description, t.OrgID, CleanList(t.Models), t.MaxBudget, t.BudgetPeriod, NextReset(t.BudgetPeriod, time.Now()),
		t.MemberMaxBudget, t.RPMLimit, t.TPMLimit, t.MaxParallel, CleanList(t.Guardrails), CleanList(t.MCPServers), t.Metadata, t.Blocked, CleanList(t.Policies))
}

func (s *Store) SoftDeleteTeam(ctx context.Context, id string) error {
	return exec(ctx, s, `UPDATE teams SET deleted_at=now(), updated_at=now() WHERE id=$1`, id)
}

func (s *Store) RestoreTeam(ctx context.Context, id string) error {
	return exec(ctx, s, `UPDATE teams SET deleted_at=NULL, updated_at=now() WHERE id=$1`, id)
}

func (s *Store) ListTeamMembers(ctx context.Context, teamID string) ([]TeamMember, error) {
	return queryAll[TeamMember](ctx, s, `SELECT m.team_id, m.user_id, m.role, m.spend, m.max_budget, m.joined_at, u.email, u.name, t.name AS team_name
		FROM team_members m JOIN users u ON u.id = m.user_id JOIN teams t ON t.id = m.team_id WHERE m.team_id::text = $1 ORDER BY u.email`, teamID)
}

func (s *Store) MembershipsForUser(ctx context.Context, userID string) ([]TeamMember, error) {
	return queryAll[TeamMember](ctx, s, `SELECT m.team_id, m.user_id, m.role, m.spend, m.max_budget, m.joined_at, u.email, u.name, t.name AS team_name
		FROM team_members m JOIN users u ON u.id = m.user_id JOIN teams t ON t.id = m.team_id
		WHERE m.user_id::text = $1 AND t.deleted_at IS NULL ORDER BY t.name`, userID)
}

func (s *Store) GetMembership(ctx context.Context, teamID, userID string) (TeamMember, error) {
	return queryOne[TeamMember](ctx, s, `SELECT m.team_id, m.user_id, m.role, m.spend, m.max_budget, m.joined_at, u.email, u.name, t.name AS team_name
		FROM team_members m JOIN users u ON u.id = m.user_id JOIN teams t ON t.id = m.team_id
		WHERE m.team_id::text = $1 AND m.user_id::text = $2`, teamID, userID)
}

func (s *Store) UpsertTeamMember(ctx context.Context, teamID, userID, role string, maxBudget *float64) error {
	if role == "" {
		role = "team_member"
	}
	return exec(ctx, s, `INSERT INTO team_members (team_id, user_id, role, max_budget) VALUES ($1,$2,$3,$4)
		ON CONFLICT (team_id, user_id) DO UPDATE SET role = EXCLUDED.role, max_budget = EXCLUDED.max_budget`, teamID, userID, role, maxBudget)
}

func (s *Store) RemoveTeamMember(ctx context.Context, teamID, userID string) error {
	return exec(ctx, s, `DELETE FROM team_members WHERE team_id=$1 AND user_id=$2`, teamID, userID)
}
