package guardrails

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrConflict is returned when a guardrail name is already taken.
var ErrConflict = errors.New("a guardrail with this name already exists")

const cols = `id::text, name, kind, mode, action, config, default_on, enabled, description, preset, created_at, updated_at`

func scanGuardrail(row pgx.Row) (Guardrail, error) {
	var g Guardrail
	var cfg []byte
	err := row.Scan(&g.ID, &g.Name, &g.Kind, &g.Mode, &g.Action, &cfg, &g.DefaultOn, &g.Enabled, &g.Description, &g.Preset, &g.CreatedAt, &g.UpdatedAt)
	if err == nil && len(cfg) > 0 {
		_ = json.Unmarshal(cfg, &g.Config)
	}
	return g, err
}

// List returns every guardrail ordered by name.
func (e *Engine) List(ctx context.Context) ([]Guardrail, error) {
	rows, err := e.pool.Query(ctx, `SELECT `+cols+` FROM guardrails ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Guardrail{}
	for rows.Next() {
		g, err := scanGuardrail(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// Get loads one guardrail by id.
func (e *Engine) Get(ctx context.Context, id string) (Guardrail, error) {
	g, err := scanGuardrail(e.pool.QueryRow(ctx, `SELECT `+cols+` FROM guardrails WHERE id::text=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return g, ErrNotFound
	}
	return g, err
}

// Save validates and inserts (empty ID) or updates a guardrail, then reloads the engine.
func (e *Engine) Save(ctx context.Context, g *Guardrail) error {
	if err := Validate(g); err != nil {
		return err
	}
	cfg, _ := json.Marshal(g.Config)
	var err error
	if g.ID == "" {
		err = e.pool.QueryRow(ctx, `INSERT INTO guardrails (name, kind, mode, action, config, default_on, enabled, description, preset)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id::text`,
			g.Name, g.Kind, g.Mode, g.Action, cfg, g.DefaultOn, g.Enabled, g.Description, g.Preset).Scan(&g.ID)
	} else {
		var tag pgconn.CommandTag
		tag, err = e.pool.Exec(ctx, `UPDATE guardrails SET name=$2, kind=$3, mode=$4, action=$5, config=$6, default_on=$7,
			enabled=$8, description=$9, updated_at=now() WHERE id::text=$1`,
			g.ID, g.Name, g.Kind, g.Mode, g.Action, cfg, g.DefaultOn, g.Enabled, g.Description)
		if err == nil && tag.RowsAffected() == 0 {
			err = ErrNotFound
		}
	}
	if err != nil {
		return mapErr(err)
	}
	return e.Reload(ctx)
}

// SetFlag toggles "enabled" or "default_on".
func (e *Engine) SetFlag(ctx context.Context, id, field string, v bool) error {
	if field != "enabled" && field != "default_on" {
		return errors.New("unknown field")
	}
	tag, err := e.pool.Exec(ctx, `UPDATE guardrails SET `+field+`=$2, updated_at=now() WHERE id::text=$1`, id, v)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return e.Reload(ctx)
}

// Delete removes a guardrail and drops it from every key, team and policy that references it.
func (e *Engine) Delete(ctx context.Context, id string) error {
	var name string
	if err := e.pool.QueryRow(ctx, `DELETE FROM guardrails WHERE id::text=$1 RETURNING name`, id).Scan(&name); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	for _, t := range []string{"api_keys", "teams", "guardrail_policies"} {
		if _, err := e.pool.Exec(ctx, `UPDATE `+t+` SET guardrails = array_remove(guardrails, $1) WHERE $1 = ANY(guardrails)`, name); err != nil {
			return err
		}
	}
	return e.Reload(ctx)
}

// Usage counts how many active keys and teams reference each guardrail by name.
func (e *Engine) Usage(ctx context.Context) map[string]int {
	out := map[string]int{}
	rows, err := e.pool.Query(ctx, `SELECT g, count(*)::int FROM (
		SELECT unnest(guardrails) AS g FROM api_keys WHERE deleted_at IS NULL
		UNION ALL SELECT unnest(guardrails) FROM teams WHERE deleted_at IS NULL
		UNION ALL SELECT unnest(guardrails) FROM guardrail_policies) t GROUP BY g`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		var c int
		if rows.Scan(&n, &c) == nil {
			out[n] = c
		}
	}
	return out
}

// EventFilter narrows the event log.
type EventFilter struct {
	Guardrail string
	Action    string
	Phase     string
	Since     time.Time
	Limit     int
}

// Events lists recent interventions, newest first.
func (e *Engine) Events(ctx context.Context, f EventFilter) ([]Event, error) {
	where := []string{"true"}
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.Replace(cond, "?", "$"+strconv.Itoa(len(args)), 1))
	}
	if f.Guardrail != "" {
		add("e.guardrail = ?", f.Guardrail)
	}
	if f.Action != "" {
		add("e.action = ?", f.Action)
	}
	if f.Phase != "" {
		add("e.phase = ?", f.Phase)
	}
	if !f.Since.IsZero() {
		add("e.at >= ?", f.Since)
	}
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	rows, err := e.pool.Query(ctx, `SELECT e.id, e.at, e.guardrail, e.request_id, coalesce(e.key_id::text,''), coalesce(nullif(k.alias,''), k.key_hint, ''),
		e.phase, e.action, e.detail
		FROM guardrail_events e LEFT JOIN api_keys k ON k.id = e.key_id
		WHERE `+strings.Join(where, " AND ")+` ORDER BY e.at DESC, e.id DESC LIMIT `+strconv.Itoa(f.Limit), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var ev Event
		if err := rows.Scan(&ev.ID, &ev.At, &ev.Guardrail, &ev.RequestID, &ev.KeyID, &ev.KeyAlias, &ev.Phase, &ev.Action, &ev.Detail); err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// EventCounts returns intervention counts by action since t, plus per-guardrail totals.
func (e *Engine) EventCounts(ctx context.Context, since time.Time) (byAction map[string]int, byGuardrail map[string]int) {
	byAction, byGuardrail = map[string]int{}, map[string]int{}
	rows, err := e.pool.Query(ctx, `SELECT guardrail, action, count(*)::int FROM guardrail_events WHERE at >= $1 GROUP BY 1,2`, since)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var g, a string
		var n int
		if rows.Scan(&g, &a, &n) == nil {
			byAction[a] += n
			byGuardrail[g] += n
		}
	}
	return
}

func mapErr(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return ErrConflict
	}
	return err
}
