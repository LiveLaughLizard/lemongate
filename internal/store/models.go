package store

import "context"

const depCols = `d.id, d.name, d.api_base, d.upstream_model, d.credential_id, d.mode, d.weight, d.rpm_limit, d.tpm_limit,
	d.max_parallel, d.timeout_seconds, d.context_window, d.max_output_tokens, d.input_cost_per_m, d.output_cost_per_m,
	d.description, d.tags, d.extra_headers, d.enabled, d.created_at, d.updated_at, c.name AS credential_name`

const depFrom = ` FROM deployments d LEFT JOIN credentials c ON c.id = d.credential_id`

func (s *Store) ListDeployments(ctx context.Context) ([]Deployment, error) {
	return queryAll[Deployment](ctx, s, `SELECT `+depCols+depFrom+` ORDER BY d.name, d.created_at`)
}

func (s *Store) GetDeployment(ctx context.Context, id string) (Deployment, error) {
	return queryOne[Deployment](ctx, s, `SELECT `+depCols+depFrom+` WHERE d.id::text = $1`, id)
}

func (s *Store) CreateDeployment(ctx context.Context, d Deployment) (Deployment, error) {
	if d.ExtraHeaders == nil {
		d.ExtraHeaders = map[string]string{}
	}
	var id string
	err := s.Pool.QueryRow(ctx, `INSERT INTO deployments (name, api_base, upstream_model, credential_id, mode, weight, rpm_limit,
		tpm_limit, max_parallel, timeout_seconds, context_window, max_output_tokens, input_cost_per_m, output_cost_per_m,
		description, tags, extra_headers, enabled) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) RETURNING id`,
		d.Name, d.APIBase, d.UpstreamModel, d.CredentialID, d.Mode, d.Weight, d.RPMLimit, d.TPMLimit, d.MaxParallel,
		d.TimeoutSeconds, d.ContextWindow, d.MaxOutputTokens, d.InputCostPerM, d.OutputCostPerM, d.Description,
		CleanList(d.Tags), d.ExtraHeaders, d.Enabled).Scan(&id)
	if err != nil {
		return Deployment{}, mapErr(err)
	}
	return s.GetDeployment(ctx, id)
}

func (s *Store) UpdateDeployment(ctx context.Context, d Deployment) error {
	if d.ExtraHeaders == nil {
		d.ExtraHeaders = map[string]string{}
	}
	return exec(ctx, s, `UPDATE deployments SET name=$2, api_base=$3, upstream_model=$4, credential_id=$5, mode=$6, weight=$7,
		rpm_limit=$8, tpm_limit=$9, max_parallel=$10, timeout_seconds=$11, context_window=$12, max_output_tokens=$13,
		input_cost_per_m=$14, output_cost_per_m=$15, description=$16, tags=$17, extra_headers=$18, enabled=$19, updated_at=now()
		WHERE id=$1`, d.ID, d.Name, d.APIBase, d.UpstreamModel, d.CredentialID, d.Mode, d.Weight, d.RPMLimit, d.TPMLimit,
		d.MaxParallel, d.TimeoutSeconds, d.ContextWindow, d.MaxOutputTokens, d.InputCostPerM, d.OutputCostPerM,
		d.Description, CleanList(d.Tags), d.ExtraHeaders, d.Enabled)
}

func (s *Store) SetDeploymentEnabled(ctx context.Context, id string, enabled bool) error {
	return exec(ctx, s, `UPDATE deployments SET enabled=$2, updated_at=now() WHERE id=$1`, id, enabled)
}

func (s *Store) DeleteDeployment(ctx context.Context, id string) error {
	return exec(ctx, s, `DELETE FROM deployments WHERE id=$1`, id)
}

func (s *Store) ListAliases(ctx context.Context) ([]Alias, error) {
	return queryAll[Alias](ctx, s, `SELECT alias, target, created_at FROM model_aliases ORDER BY alias`)
}

func (s *Store) UpsertAlias(ctx context.Context, alias, target string) error {
	return exec(ctx, s, `INSERT INTO model_aliases (alias, target) VALUES ($1,$2) ON CONFLICT (alias) DO UPDATE SET target = EXCLUDED.target`, alias, target)
}

func (s *Store) DeleteAlias(ctx context.Context, alias string) error {
	return exec(ctx, s, `DELETE FROM model_aliases WHERE alias=$1`, alias)
}

func (s *Store) ListAccessGroups(ctx context.Context) ([]AccessGroup, error) {
	return queryAll[AccessGroup](ctx, s, `SELECT name, description, models, created_at FROM access_groups ORDER BY name`)
}

func (s *Store) UpsertAccessGroup(ctx context.Context, g AccessGroup) error {
	return exec(ctx, s, `INSERT INTO access_groups (name, description, models) VALUES ($1,$2,$3)
		ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, models = EXCLUDED.models`, g.Name, g.Description, CleanList(g.Models))
}

func (s *Store) DeleteAccessGroup(ctx context.Context, name string) error {
	return exec(ctx, s, `DELETE FROM access_groups WHERE name=$1`, name)
}

func (s *Store) ListFallbacks(ctx context.Context) ([]Fallback, error) {
	return queryAll[Fallback](ctx, s, `SELECT model, kind, targets FROM model_fallbacks ORDER BY model, kind`)
}

func (s *Store) UpsertFallback(ctx context.Context, f Fallback) error {
	if f.Kind == "" {
		f.Kind = "general"
	}
	return exec(ctx, s, `INSERT INTO model_fallbacks (model, kind, targets) VALUES ($1,$2,$3)
		ON CONFLICT (model, kind) DO UPDATE SET targets = EXCLUDED.targets`, f.Model, f.Kind, CleanList(f.Targets))
}

func (s *Store) DeleteFallback(ctx context.Context, model, kind string) error {
	return exec(ctx, s, `DELETE FROM model_fallbacks WHERE model=$1 AND kind=$2`, model, kind)
}
