package store

import (
	"context"
	"time"
)

const keyCols = `k.id, k.key_hash, k.key_hint, k.alias, k.scope, k.user_id, k.team_id, k.models, k.access_groups,
	k.max_budget, k.budget_period, k.budget_reset_at, k.spend, k.rpm_limit, k.tpm_limit, k.max_parallel,
	k.expires_at, k.metadata, k.tags, k.guardrails, k.policies, k.mcp_servers, k.blocked, k.last_used_at, k.created_by,
	k.created_at, k.updated_at, k.deleted_at, u.email AS user_email, t.name AS team_name`

const keyFrom = ` FROM api_keys k LEFT JOIN users u ON u.id = k.user_id LEFT JOIN teams t ON t.id = k.team_id`

type KeyFilter struct {
	UserID  string
	TeamID  string
	Search  string
	Deleted bool
	Limit   int
	Offset  int
}

func (s *Store) ListKeys(ctx context.Context, f KeyFilter) ([]Key, error) {
	q := `SELECT ` + keyCols + keyFrom + ` WHERE ($1 = '' OR k.user_id::text = $1) AND ($2 = '' OR k.team_id::text = $2)
		AND ($3 = '' OR k.alias ILIKE '%'||$3||'%' OR k.key_hint ILIKE '%'||$3||'%' OR u.email ILIKE '%'||$3||'%' OR t.name ILIKE '%'||$3||'%')
		AND (k.deleted_at IS NOT NULL) = $4 ORDER BY k.created_at DESC LIMIT $5 OFFSET $6`
	if f.Limit <= 0 {
		f.Limit = 500
	}
	return queryAll[Key](ctx, s, q, f.UserID, f.TeamID, f.Search, f.Deleted, f.Limit, f.Offset)
}

func (s *Store) GetKey(ctx context.Context, id string) (Key, error) {
	return queryOne[Key](ctx, s, `SELECT `+keyCols+keyFrom+` WHERE k.id::text = $1`, id)
}

func (s *Store) GetKeyByHash(ctx context.Context, hash string) (Key, error) {
	return queryOne[Key](ctx, s, `SELECT `+keyCols+keyFrom+` WHERE k.key_hash = $1 AND k.deleted_at IS NULL`, hash)
}

func (s *Store) CreateKey(ctx context.Context, k Key) (Key, error) {
	if k.Metadata == nil {
		k.Metadata = map[string]any{}
	}
	var id string
	err := s.Pool.QueryRow(ctx, `INSERT INTO api_keys (key_hash, key_hint, alias, scope, user_id, team_id, models, access_groups,
		max_budget, budget_period, budget_reset_at, rpm_limit, tpm_limit, max_parallel, expires_at, metadata, tags, guardrails,
		mcp_servers, blocked, created_by, policies)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22) RETURNING id`,
		k.KeyHash, k.KeyHint, k.Alias, k.Scope, k.UserID, k.TeamID, CleanList(k.Models), CleanList(k.AccessGroups),
		k.MaxBudget, k.BudgetPeriod, NextReset(k.BudgetPeriod, time.Now()), k.RPMLimit, k.TPMLimit, k.MaxParallel, k.ExpiresAt,
		k.Metadata, CleanList(k.Tags), CleanList(k.Guardrails), CleanList(k.MCPServers), k.Blocked, k.CreatedBy, CleanList(k.Policies)).Scan(&id)
	if err != nil {
		return Key{}, mapErr(err)
	}
	return s.GetKey(ctx, id)
}

// UpdateKey writes every editable field (not the hash, spend, or ownership audit fields).
func (s *Store) UpdateKey(ctx context.Context, k Key) error {
	if k.Metadata == nil {
		k.Metadata = map[string]any{}
	}
	return exec(ctx, s, `UPDATE api_keys SET alias=$2, scope=$3, user_id=$4, team_id=$5, models=$6, access_groups=$7,
		max_budget=$8, budget_period=$9, budget_reset_at = CASE WHEN budget_period IS DISTINCT FROM $9 THEN $10 ELSE budget_reset_at END,
		rpm_limit=$11, tpm_limit=$12, max_parallel=$13, expires_at=$14, metadata=$15, tags=$16, guardrails=$17,
		mcp_servers=$18, blocked=$19, policies=$20, updated_at=now() WHERE id=$1`,
		k.ID, k.Alias, k.Scope, k.UserID, k.TeamID, CleanList(k.Models), CleanList(k.AccessGroups), k.MaxBudget,
		k.BudgetPeriod, NextReset(k.BudgetPeriod, time.Now()), k.RPMLimit, k.TPMLimit, k.MaxParallel, k.ExpiresAt,
		k.Metadata, CleanList(k.Tags), CleanList(k.Guardrails), CleanList(k.MCPServers), k.Blocked, CleanList(k.Policies))
}

func (s *Store) SetKeyBlocked(ctx context.Context, id string, blocked bool) error {
	return exec(ctx, s, `UPDATE api_keys SET blocked=$2, updated_at=now() WHERE id=$1`, id, blocked)
}

func (s *Store) RotateKey(ctx context.Context, id, hash, hint string) error {
	return exec(ctx, s, `UPDATE api_keys SET key_hash=$2, key_hint=$3, updated_at=now() WHERE id=$1`, id, hash, hint)
}

func (s *Store) SoftDeleteKey(ctx context.Context, id string) error {
	return exec(ctx, s, `UPDATE api_keys SET deleted_at=now(), updated_at=now() WHERE id=$1 AND deleted_at IS NULL`, id)
}

func (s *Store) RestoreKey(ctx context.Context, id string) error {
	return exec(ctx, s, `UPDATE api_keys SET deleted_at=NULL, updated_at=now() WHERE id=$1`, id)
}

func (s *Store) PurgeKey(ctx context.Context, id string) error {
	return exec(ctx, s, `DELETE FROM api_keys WHERE id=$1`, id)
}

func (s *Store) ResetKeySpend(ctx context.Context, id string) error {
	return exec(ctx, s, `UPDATE api_keys SET spend=0, updated_at=now() WHERE id=$1`, id)
}

func (s *Store) TouchKeys(ctx context.Context, ids []string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE api_keys SET last_used_at=now() WHERE id = ANY($1::uuid[])`, ids)
	return err
}

func (s *Store) KeysExpiringWithin(ctx context.Context, d time.Duration) ([]Key, error) {
	return queryAll[Key](ctx, s, `SELECT `+keyCols+keyFrom+` WHERE k.deleted_at IS NULL AND k.expires_at IS NOT NULL
		AND k.expires_at > now() AND k.expires_at < now() + $1::interval`, d.String())
}
