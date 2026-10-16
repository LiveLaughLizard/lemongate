package store

import (
	"context"
	"time"
)

const userCols = `u.id, u.email, u.name, u.role, u.password_hash, u.sso_subject, u.org_id, u.models, u.max_budget,
	u.budget_period, u.budget_reset_at, u.spend, u.rpm_limit, u.tpm_limit, u.max_parallel, u.metadata, u.blocked,
	u.last_login_at, u.created_at, u.updated_at,
	(SELECT count(*) FROM api_keys k WHERE k.user_id = u.id AND k.deleted_at IS NULL)::int AS key_count,
	o.name AS org_name`

const userFrom = ` FROM users u LEFT JOIN organizations o ON o.id = u.org_id`

func (s *Store) ListUsers(ctx context.Context, search, role string) ([]User, error) {
	return queryAll[User](ctx, s, `SELECT `+userCols+userFrom+` WHERE ($1 = '' OR u.email ILIKE '%'||$1||'%' OR u.name ILIKE '%'||$1||'%')
		AND ($2 = '' OR u.role = $2) ORDER BY u.created_at DESC`, search, role)
}

func (s *Store) GetUser(ctx context.Context, id string) (User, error) {
	return queryOne[User](ctx, s, `SELECT `+userCols+userFrom+` WHERE u.id::text = $1`, id)
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (User, error) {
	return queryOne[User](ctx, s, `SELECT `+userCols+userFrom+` WHERE lower(u.email) = lower($1)`, email)
}

func (s *Store) GetUserBySSO(ctx context.Context, subject string) (User, error) {
	return queryOne[User](ctx, s, `SELECT `+userCols+userFrom+` WHERE u.sso_subject = $1`, subject)
}

func (s *Store) CreateUser(ctx context.Context, u User) (User, error) {
	if u.Metadata == nil {
		u.Metadata = map[string]any{}
	}
	if u.Role == "" {
		u.Role = "member"
	}
	var id string
	err := s.Pool.QueryRow(ctx, `INSERT INTO users (email, name, role, password_hash, sso_subject, org_id, models, max_budget,
		budget_period, budget_reset_at, rpm_limit, tpm_limit, max_parallel, metadata, blocked)
		VALUES (lower($1),$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING id`,
		u.Email, u.Name, u.Role, u.PasswordHash, u.SSOSubject, u.OrgID, CleanList(u.Models), u.MaxBudget, u.BudgetPeriod,
		NextReset(u.BudgetPeriod, time.Now()), u.RPMLimit, u.TPMLimit, u.MaxParallel, u.Metadata, u.Blocked).Scan(&id)
	if err != nil {
		return User{}, mapErr(err)
	}
	return s.GetUser(ctx, id)
}

func (s *Store) UpdateUser(ctx context.Context, u User) error {
	if u.Metadata == nil {
		u.Metadata = map[string]any{}
	}
	return exec(ctx, s, `UPDATE users SET email=lower($2), name=$3, role=$4, org_id=$5, models=$6, max_budget=$7, budget_period=$8,
		budget_reset_at = CASE WHEN budget_period IS DISTINCT FROM $8 THEN $9 ELSE budget_reset_at END,
		rpm_limit=$10, tpm_limit=$11, max_parallel=$12, metadata=$13, blocked=$14, updated_at=now() WHERE id=$1`,
		u.ID, u.Email, u.Name, u.Role, u.OrgID, CleanList(u.Models), u.MaxBudget, u.BudgetPeriod,
		NextReset(u.BudgetPeriod, time.Now()), u.RPMLimit, u.TPMLimit, u.MaxParallel, u.Metadata, u.Blocked)
}

func (s *Store) SetUserPassword(ctx context.Context, id, hash string) error {
	return exec(ctx, s, `UPDATE users SET password_hash=$2, updated_at=now() WHERE id=$1`, id, hash)
}

func (s *Store) LinkUserSSO(ctx context.Context, id, subject string) error {
	return exec(ctx, s, `UPDATE users SET sso_subject=$2, updated_at=now() WHERE id=$1`, id, subject)
}

func (s *Store) TouchUserLogin(ctx context.Context, id string) error {
	return exec(ctx, s, `UPDATE users SET last_login_at=now() WHERE id=$1`, id)
}

// DeleteUser deletes a user and soft-deletes their keys, so the keys of an offboarded
// (or previously blocked) user cannot keep working without an owner.
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	return s.deleteOwner(ctx, `UPDATE api_keys SET deleted_at=now(), updated_at=now() WHERE user_id=$1 AND deleted_at IS NULL`,
		`DELETE FROM users WHERE id=$1`, id)
}

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}
