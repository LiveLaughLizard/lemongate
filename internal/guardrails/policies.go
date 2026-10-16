package guardrails

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Policy is a named bundle of guardrails. Keys and teams reference policies by name,
// and a default-on policy applies to every call. Presets install as a policy.
type Policy struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Guardrails  []string  `json:"guardrails"`
	Preset      string    `json:"preset"`
	DefaultOn   bool      `json:"default_on"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

const policyCols = `id::text, name, description, guardrails, preset, default_on, enabled, created_at, updated_at`

func scanPolicy(row pgx.Row) (Policy, error) {
	var p Policy
	err := row.Scan(&p.ID, &p.Name, &p.Description, &p.Guardrails, &p.Preset, &p.DefaultOn, &p.Enabled, &p.CreatedAt, &p.UpdatedAt)
	return p, err
}

// ListPolicies returns every policy ordered by name.
func (e *Engine) ListPolicies(ctx context.Context) ([]Policy, error) {
	rows, err := e.pool.Query(ctx, `SELECT `+policyCols+` FROM guardrail_policies ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Policy{}
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetPolicy loads a policy by id or name.
func (e *Engine) GetPolicy(ctx context.Context, idOrName string) (Policy, error) {
	p, err := scanPolicy(e.pool.QueryRow(ctx, `SELECT `+policyCols+` FROM guardrail_policies WHERE id::text=$1 OR name=$1`, idOrName))
	if errors.Is(err, pgx.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

// ValidatePolicy normalizes a policy and checks that its guardrails exist.
func (e *Engine) ValidatePolicy(ctx context.Context, p *Policy) error {
	p.Name = strings.TrimSpace(p.Name)
	if !nameRe.MatchString(p.Name) {
		return errors.New("name must be 1–63 characters: letters, digits, '-', '_' or '.'")
	}
	p.Guardrails = cleanList(p.Guardrails)
	if len(p.Guardrails) == 0 {
		return errors.New("a policy needs at least one guardrail")
	}
	var missing []string
	for _, g := range p.Guardrails {
		var exists bool
		if err := e.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM guardrails WHERE name=$1)`, g).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			missing = append(missing, g)
		}
	}
	if len(missing) > 0 {
		return errors.New("unknown guardrails: " + strings.Join(missing, ", "))
	}
	return nil
}

// SavePolicy inserts (empty ID) or updates a policy, then reloads the engine.
// Renaming a policy updates references on keys and teams.
func (e *Engine) SavePolicy(ctx context.Context, p *Policy) error {
	if err := e.ValidatePolicy(ctx, p); err != nil {
		return err
	}
	tx, err := e.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if p.ID == "" {
		err = tx.QueryRow(ctx, `INSERT INTO guardrail_policies (name, description, guardrails, preset, default_on, enabled)
			VALUES ($1,$2,$3,$4,$5,$6) RETURNING id::text`, p.Name, p.Description, p.Guardrails, p.Preset, p.DefaultOn, p.Enabled).Scan(&p.ID)
	} else {
		var old string
		if err = tx.QueryRow(ctx, `SELECT name FROM guardrail_policies WHERE id::text=$1`, p.ID).Scan(&old); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE guardrail_policies SET name=$2, description=$3, guardrails=$4, default_on=$5, enabled=$6,
			updated_at=now() WHERE id::text=$1`, p.ID, p.Name, p.Description, p.Guardrails, p.DefaultOn, p.Enabled)
		if err == nil && old != p.Name {
			err = renamePolicyRefs(ctx, tx, old, p.Name)
		}
	}
	if err != nil {
		return mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return e.Reload(ctx)
}

func renamePolicyRefs(ctx context.Context, tx pgx.Tx, old, name string) error {
	for _, t := range []string{"api_keys", "teams"} {
		var newName any = name
		if name == "" {
			newName = nil
		}
		q := `UPDATE ` + t + ` SET policies = array_remove(array_replace(policies, $1, $2), NULL) WHERE $1 = ANY(policies)`
		if _, err := tx.Exec(ctx, q, old, newName); err != nil {
			return err
		}
	}
	return nil
}

// SetPolicyFlag toggles "enabled" or "default_on".
func (e *Engine) SetPolicyFlag(ctx context.Context, id, field string, v bool) error {
	if field != "enabled" && field != "default_on" {
		return errors.New("unknown flag")
	}
	tag, err := e.pool.Exec(ctx, `UPDATE guardrail_policies SET `+field+`=$2, updated_at=now() WHERE id::text=$1`, id, v)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return e.Reload(ctx)
}

// DeletePolicy removes a policy and its references on keys and teams. With
// withGuardrails, guardrails used only by this policy are deleted as well.
func (e *Engine) DeletePolicy(ctx context.Context, id string, withGuardrails bool) error {
	p, err := e.GetPolicy(ctx, id)
	if err != nil {
		return err
	}
	tx, err := e.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM guardrail_policies WHERE id::text=$1`, p.ID); err != nil {
		return err
	}
	if err := renamePolicyRefs(ctx, tx, p.Name, ""); err != nil {
		return err
	}
	if withGuardrails {
		for _, g := range p.Guardrails {
			var shared bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM guardrail_policies WHERE $1 = ANY(guardrails))`, g).Scan(&shared); err != nil {
				return err
			}
			if !shared {
				if _, err := tx.Exec(ctx, `DELETE FROM guardrails WHERE name=$1`, g); err != nil {
					return err
				}
				for _, t := range []string{"api_keys", "teams"} {
					if _, err := tx.Exec(ctx, `UPDATE `+t+` SET guardrails = array_remove(guardrails, $1) WHERE $1 = ANY(guardrails)`, g); err != nil {
						return err
					}
				}
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return e.Reload(ctx)
}

// PolicyNames returns the names of enabled policies.
func (e *Engine) PolicyNames() []string {
	st := e.state.Load()
	out := make([]string, 0, len(st.policies))
	for n := range st.policies {
		out = append(out, n)
	}
	return cleanSorted(out)
}

func cleanSorted(xs []string) []string {
	out := cleanList(xs)
	sort.Strings(out)
	return out
}
