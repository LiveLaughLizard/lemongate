package store

import (
	"context"
	"time"
)

// CredentialRef is one place a credential is referenced.
type CredentialRef struct {
	Kind string `db:"kind" json:"kind"` // deployment | mcp_server | passthrough
	ID   string `db:"id" json:"id"`
	Name string `db:"name" json:"name"`
}

// CredentialUsage lists every deployment, MCP server and pass-through route using a credential.
func (s *Store) CredentialUsage(ctx context.Context, id string) ([]CredentialRef, error) {
	return queryAll[CredentialRef](ctx, s, `
		SELECT 'deployment' AS kind, d.id::text AS id, d.name || ' → ' || d.api_base AS name FROM deployments d WHERE d.credential_id::text = $1
		UNION ALL SELECT 'mcp_server', m.id::text, m.name FROM mcp_servers m WHERE m.credential_id::text = $1
		UNION ALL SELECT 'passthrough', p.id::text, p.name FROM passthrough_routes p WHERE p.credential_id::text = $1
		ORDER BY 1, 3`, id)
}

// HealthCheck is one persisted health probe result.
type HealthCheck struct {
	ID           int64     `db:"id" json:"id"`
	DeploymentID string    `db:"deployment_id" json:"deployment_id"`
	CheckedAt    time.Time `db:"checked_at" json:"checked_at"`
	OK           bool      `db:"ok" json:"ok"`
	LatencyMs    int       `db:"latency_ms" json:"latency_ms"`
	Error        string    `db:"error" json:"error"`
}

// HealthHistory returns the most recent checks for the given deployments, newest first.
func (s *Store) HealthHistory(ctx context.Context, deploymentIDs []string, limit int) ([]HealthCheck, error) {
	if limit <= 0 {
		limit = 200
	}
	if deploymentIDs == nil {
		deploymentIDs = []string{}
	}
	return queryAll[HealthCheck](ctx, s, `SELECT id, deployment_id::text AS deployment_id, checked_at, ok, latency_ms, error
		FROM health_checks WHERE deployment_id::text = ANY($1::text[]) ORDER BY checked_at DESC LIMIT $2`, deploymentIDs, limit)
}

// CountAudit counts audit entries matching the same filters as ListAudit.
func (s *Store) CountAudit(ctx context.Context, entityType, search string) (int, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_log
		WHERE ($1 = '' OR entity_type = $1) AND ($2 = '' OR summary ILIKE '%'||$2||'%' OR actor_label ILIKE '%'||$2||'%' OR entity_id = $2)`,
		entityType, search).Scan(&n)
	return n, err
}

// AuditEntityTypes lists the distinct entity types present in the audit log.
func (s *Store) AuditEntityTypes(ctx context.Context) ([]string, error) {
	rows, err := s.Pool.Query(ctx, `SELECT DISTINCT entity_type FROM audit_log ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if rows.Scan(&t) == nil {
			out = append(out, t)
		}
	}
	return out, rows.Err()
}

// ListAuditFiltered extends ListAudit with action and actor filters.
func (s *Store) ListAuditFiltered(ctx context.Context, entityType, action, search string, limit, offset int) ([]AuditEntry, int, error) {
	if limit <= 0 {
		limit = 50
	}
	where := `WHERE ($1 = '' OR entity_type = $1) AND ($2 = '' OR action = $2) AND ($3 = '' OR summary ILIKE '%'||$3||'%'
		OR actor_label ILIKE '%'||$3||'%' OR entity_id = $3)`
	var n int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_log `+where, entityType, action, search).Scan(&n); err != nil {
		return nil, 0, err
	}
	list, err := queryAll[AuditEntry](ctx, s, `SELECT id, at, actor_id, actor_label, action, entity_type, entity_id, summary, before, after
		FROM audit_log `+where+` ORDER BY at DESC, id DESC LIMIT $4 OFFSET $5`, entityType, action, search, limit, offset)
	return list, n, err
}

// AuditActions lists the distinct actions present in the audit log.
func (s *Store) AuditActions(ctx context.Context) ([]string, error) {
	rows, err := s.Pool.Query(ctx, `SELECT DISTINCT action FROM audit_log ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if rows.Scan(&t) == nil {
			out = append(out, t)
		}
	}
	return out, rows.Err()
}

// DeploymentRequestStats summarizes recent request logs per deployment (last 24h).
type DeploymentStat struct {
	DeploymentID string  `db:"deployment_id"`
	Requests     int64   `db:"requests"`
	Failures     int64   `db:"failures"`
	AvgLatencyMs float64 `db:"avg_latency_ms"`
}

func (s *Store) DeploymentStats24h(ctx context.Context) (map[string]DeploymentStat, error) {
	list, err := queryAll[DeploymentStat](ctx, s, `SELECT deployment_id::text AS deployment_id, count(*)::bigint AS requests,
		count(*) FILTER (WHERE status <> 'success')::bigint AS failures, COALESCE(avg(latency_ms),0)::float8 AS avg_latency_ms
		FROM request_logs WHERE created_at > now() - interval '24 hours' AND deployment_id IS NOT NULL GROUP BY deployment_id`)
	out := map[string]DeploymentStat{}
	for _, d := range list {
		out[d.DeploymentID] = d
	}
	return out, err
}
