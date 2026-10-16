package store

import (
	"context"
	"time"
)

const orgCols = `o.id, o.name, o.description, o.models, o.max_budget, o.budget_period, o.budget_reset_at, o.spend,
	o.rpm_limit, o.tpm_limit, o.metadata, o.blocked, o.created_at, o.updated_at,
	(SELECT count(*) FROM teams t WHERE t.org_id = o.id AND t.deleted_at IS NULL)::int AS team_count,
	(SELECT count(*) FROM users u WHERE u.org_id = o.id)::int AS user_count`

func (s *Store) ListOrgs(ctx context.Context) ([]Organization, error) {
	return queryAll[Organization](ctx, s, `SELECT `+orgCols+` FROM organizations o ORDER BY o.name`)
}

func (s *Store) GetOrg(ctx context.Context, id string) (Organization, error) {
	return queryOne[Organization](ctx, s, `SELECT `+orgCols+` FROM organizations o WHERE o.id::text = $1`, id)
}

func (s *Store) CreateOrg(ctx context.Context, o Organization) (Organization, error) {
	if o.Metadata == nil {
		o.Metadata = map[string]any{}
	}
	var id string
	err := s.Pool.QueryRow(ctx, `INSERT INTO organizations (name, description, models, max_budget, budget_period, budget_reset_at,
		rpm_limit, tpm_limit, metadata, blocked) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`,
		o.Name, o.Description, CleanList(o.Models), o.MaxBudget, o.BudgetPeriod, NextReset(o.BudgetPeriod, time.Now()),
		o.RPMLimit, o.TPMLimit, o.Metadata, o.Blocked).Scan(&id)
	if err != nil {
		return Organization{}, mapErr(err)
	}
	return s.GetOrg(ctx, id)
}

func (s *Store) UpdateOrg(ctx context.Context, o Organization) error {
	if o.Metadata == nil {
		o.Metadata = map[string]any{}
	}
	return exec(ctx, s, `UPDATE organizations SET name=$2, description=$3, models=$4, max_budget=$5, budget_period=$6,
		budget_reset_at = CASE WHEN budget_period IS DISTINCT FROM $6 THEN $7 ELSE budget_reset_at END,
		rpm_limit=$8, tpm_limit=$9, metadata=$10, blocked=$11, updated_at=now() WHERE id=$1`,
		o.ID, o.Name, o.Description, CleanList(o.Models), o.MaxBudget, o.BudgetPeriod, NextReset(o.BudgetPeriod, time.Now()),
		o.RPMLimit, o.TPMLimit, o.Metadata, o.Blocked)
}

func (s *Store) DeleteOrg(ctx context.Context, id string) error {
	return exec(ctx, s, `DELETE FROM organizations WHERE id=$1`, id)
}
