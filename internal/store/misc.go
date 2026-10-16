package store

import (
	"context"
	"encoding/json"
	"time"
)

// --- credentials ---

func (s *Store) ListCredentials(ctx context.Context) ([]Credential, error) {
	return queryAll[Credential](ctx, s, `SELECT c.id, c.name, c.description, c.secret_enc, c.hint, c.created_at, c.updated_at,
		((SELECT count(*) FROM deployments d WHERE d.credential_id = c.id) +
		 (SELECT count(*) FROM mcp_servers m WHERE m.credential_id = c.id) +
		 (SELECT count(*) FROM passthrough_routes p WHERE p.credential_id = c.id))::int AS usage_count
		FROM credentials c ORDER BY c.name`)
}

func (s *Store) GetCredential(ctx context.Context, id string) (Credential, error) {
	return queryOne[Credential](ctx, s, `SELECT id, name, description, secret_enc, hint, created_at, updated_at FROM credentials WHERE id::text=$1`, id)
}

func (s *Store) CreateCredential(ctx context.Context, c Credential) (Credential, error) {
	var id string
	if err := s.Pool.QueryRow(ctx, `INSERT INTO credentials (name, description, secret_enc, hint) VALUES ($1,$2,$3,$4) RETURNING id`,
		c.Name, c.Description, c.SecretEnc, c.Hint).Scan(&id); err != nil {
		return Credential{}, mapErr(err)
	}
	return s.GetCredential(ctx, id)
}

func (s *Store) UpdateCredential(ctx context.Context, c Credential) error {
	if c.SecretEnc == nil {
		return exec(ctx, s, `UPDATE credentials SET name=$2, description=$3, updated_at=now() WHERE id=$1`, c.ID, c.Name, c.Description)
	}
	return exec(ctx, s, `UPDATE credentials SET name=$2, description=$3, secret_enc=$4, hint=$5, updated_at=now() WHERE id=$1`,
		c.ID, c.Name, c.Description, c.SecretEnc, c.Hint)
}

func (s *Store) DeleteCredential(ctx context.Context, id string) error {
	return exec(ctx, s, `DELETE FROM credentials WHERE id=$1`, id)
}

// --- end users ---

func (s *Store) ListEndUsers(ctx context.Context, search string) ([]EndUser, error) {
	return queryAll[EndUser](ctx, s, `SELECT id, alias, max_budget, budget_period, budget_reset_at, spend, blocked, first_seen_at, last_seen_at
		FROM end_users WHERE ($1 = '' OR id ILIKE '%'||$1||'%' OR alias ILIKE '%'||$1||'%') ORDER BY last_seen_at DESC LIMIT 1000`, search)
}

func (s *Store) GetEndUser(ctx context.Context, id string) (EndUser, error) {
	return queryOne[EndUser](ctx, s, `SELECT id, alias, max_budget, budget_period, budget_reset_at, spend, blocked, first_seen_at, last_seen_at
		FROM end_users WHERE id=$1`, id)
}

func (s *Store) UpsertEndUser(ctx context.Context, e EndUser) error {
	return exec(ctx, s, `INSERT INTO end_users (id, alias, max_budget, budget_period, budget_reset_at, blocked) VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (id) DO UPDATE SET alias=EXCLUDED.alias, max_budget=EXCLUDED.max_budget, budget_period=EXCLUDED.budget_period,
		budget_reset_at = CASE WHEN end_users.budget_period IS DISTINCT FROM EXCLUDED.budget_period THEN EXCLUDED.budget_reset_at ELSE end_users.budget_reset_at END,
		blocked=EXCLUDED.blocked`,
		e.ID, e.Alias, e.MaxBudget, e.BudgetPeriod, NextReset(e.BudgetPeriod, time.Now()), e.Blocked)
}

func (s *Store) DeleteEndUser(ctx context.Context, id string) error {
	return exec(ctx, s, `DELETE FROM end_users WHERE id=$1`, id)
}

// --- tags ---

func (s *Store) ListTags(ctx context.Context) ([]Tag, error) {
	return queryAll[Tag](ctx, s, `SELECT name, description, color, max_budget, budget_period, budget_reset_at, spend, created_at FROM tags ORDER BY name`)
}

func (s *Store) GetTag(ctx context.Context, name string) (Tag, error) {
	return queryOne[Tag](ctx, s, `SELECT name, description, color, max_budget, budget_period, budget_reset_at, spend, created_at FROM tags WHERE name=$1`, name)
}

func (s *Store) UpsertTag(ctx context.Context, t Tag) error {
	return exec(ctx, s, `INSERT INTO tags (name, description, color, max_budget, budget_period, budget_reset_at) VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (name) DO UPDATE SET description=EXCLUDED.description, color=EXCLUDED.color, max_budget=EXCLUDED.max_budget,
		budget_period=EXCLUDED.budget_period,
		budget_reset_at = CASE WHEN tags.budget_period IS DISTINCT FROM EXCLUDED.budget_period THEN EXCLUDED.budget_reset_at ELSE tags.budget_reset_at END`,
		t.Name, t.Description, t.Color, t.MaxBudget, t.BudgetPeriod, NextReset(t.BudgetPeriod, time.Now()))
}

func (s *Store) DeleteTag(ctx context.Context, name string) error {
	return exec(ctx, s, `DELETE FROM tags WHERE name=$1`, name)
}

// --- budget presets ---

func (s *Store) ListBudgetPresets(ctx context.Context) ([]BudgetPreset, error) {
	return queryAll[BudgetPreset](ctx, s, `SELECT id, name, max_budget, budget_period, rpm_limit, tpm_limit, max_parallel, created_at FROM budget_presets ORDER BY name`)
}

func (s *Store) GetBudgetPreset(ctx context.Context, id string) (BudgetPreset, error) {
	return queryOne[BudgetPreset](ctx, s, `SELECT id, name, max_budget, budget_period, rpm_limit, tpm_limit, max_parallel, created_at FROM budget_presets WHERE id::text=$1`, id)
}

func (s *Store) SaveBudgetPreset(ctx context.Context, b BudgetPreset) error {
	if b.ID == "" {
		return exec(ctx, s, `INSERT INTO budget_presets (name, max_budget, budget_period, rpm_limit, tpm_limit, max_parallel) VALUES ($1,$2,$3,$4,$5,$6)`,
			b.Name, b.MaxBudget, b.BudgetPeriod, b.RPMLimit, b.TPMLimit, b.MaxParallel)
	}
	return exec(ctx, s, `UPDATE budget_presets SET name=$2, max_budget=$3, budget_period=$4, rpm_limit=$5, tpm_limit=$6, max_parallel=$7 WHERE id=$1`,
		b.ID, b.Name, b.MaxBudget, b.BudgetPeriod, b.RPMLimit, b.TPMLimit, b.MaxParallel)
}

func (s *Store) DeleteBudgetPreset(ctx context.Context, id string) error {
	return exec(ctx, s, `DELETE FROM budget_presets WHERE id=$1`, id)
}

// --- sessions & invites ---

func (s *Store) CreateSession(ctx context.Context, sess Session, ip, ua string) error {
	return exec(ctx, s, `INSERT INTO sessions (token_hash, user_id, is_master, csrf_token, ip, user_agent, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		sess.TokenHash, sess.UserID, sess.IsMaster, sess.CSRFToken, ip, ua, sess.ExpiresAt)
}

func (s *Store) GetSession(ctx context.Context, tokenHash string) (Session, error) {
	return queryOne[Session](ctx, s, `SELECT token_hash, user_id, is_master, csrf_token, created_at, expires_at FROM sessions
		WHERE token_hash=$1 AND expires_at > now()`, tokenHash)
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash=$1`, tokenHash)
	return err
}

func (s *Store) DeleteUserSessions(ctx context.Context, userID string) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1`, userID)
	return err
}

func (s *Store) PurgeExpiredSessions(ctx context.Context) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at < now()`)
	return err
}

func (s *Store) CreateInvite(ctx context.Context, tokenHash, userID, by string, expires time.Time) error {
	return exec(ctx, s, `INSERT INTO invites (token_hash, user_id, created_by, expires_at) VALUES ($1,$2,$3,$4)`, tokenHash, userID, by, expires)
}

// ConsumeInvite marks the invite used and returns its user id.
func (s *Store) ConsumeInvite(ctx context.Context, tokenHash string) (string, error) {
	var uid string
	err := s.Pool.QueryRow(ctx, `UPDATE invites SET used_at=now() WHERE token_hash=$1 AND used_at IS NULL AND expires_at > now() RETURNING user_id`, tokenHash).Scan(&uid)
	if err != nil {
		return "", ErrNotFound
	}
	return uid, nil
}

func (s *Store) PeekInvite(ctx context.Context, tokenHash string) (string, error) {
	var uid string
	err := s.Pool.QueryRow(ctx, `SELECT user_id FROM invites WHERE token_hash=$1 AND used_at IS NULL AND expires_at > now()`, tokenHash).Scan(&uid)
	if err != nil {
		return "", ErrNotFound
	}
	return uid, nil
}

// --- audit ---

func (s *Store) Audit(ctx context.Context, actorID, actorLabel, action, entityType, entityID, summary string, before, after any) {
	toMap := func(v any) map[string]any {
		if v == nil {
			return nil
		}
		b, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		m := map[string]any{}
		if json.Unmarshal(b, &m) != nil {
			return nil
		}
		return m
	}
	_, _ = s.Pool.Exec(ctx, `INSERT INTO audit_log (actor_id, actor_label, action, entity_type, entity_id, summary, before, after)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, actorID, actorLabel, action, entityType, entityID, summary, toMap(before), toMap(after))
}

func (s *Store) ListAudit(ctx context.Context, entityType, search string, limit, offset int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	return queryAll[AuditEntry](ctx, s, `SELECT id, at, actor_id, actor_label, action, entity_type, entity_id, summary, before, after FROM audit_log
		WHERE ($1 = '' OR entity_type = $1) AND ($2 = '' OR summary ILIKE '%'||$2||'%' OR actor_label ILIKE '%'||$2||'%' OR entity_id = $2)
		ORDER BY at DESC LIMIT $3 OFFSET $4`, entityType, search, limit, offset)
}
