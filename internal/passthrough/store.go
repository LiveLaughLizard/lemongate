package passthrough

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Route is a persisted pass-through route (table passthrough_routes).
type Route struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	TargetURL      string            `json:"target_url"`
	CredentialID   *string           `json:"credential_id"`
	CredentialName string            `json:"credential_name"`
	AuthHeader     string            `json:"auth_header"`
	AuthPrefix     string            `json:"auth_prefix"`
	ExtraHeaders   map[string]string `json:"extra_headers"`
	RequireKey     bool              `json:"require_key"`
	CostPerRequest float64           `json:"cost_per_request"`
	Description    string            `json:"description"`
	Enabled        bool              `json:"enabled"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

var (
	ErrNotFound = errors.New("pass-through route not found")
	ErrConflict = errors.New("a route with this name already exists")
)

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_\-]{0,62}$`)

// Validate normalizes and checks a route definition.
func Validate(r *Route) error {
	r.Name = strings.ToLower(strings.TrimSpace(r.Name))
	r.TargetURL = strings.TrimSpace(r.TargetURL)
	r.AuthHeader = strings.TrimSpace(r.AuthHeader)
	if !nameRe.MatchString(r.Name) {
		return errors.New("name must be 1–63 lowercase letters, digits, '-' or '_' (it becomes part of the URL)")
	}
	u, err := url.Parse(r.TargetURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("target URL must be an absolute http(s) URL, e.g. http://10.0.0.5:8000")
	}
	if u.Fragment != "" || u.User != nil {
		return errors.New("target URL must not contain credentials or a #fragment; use a credential instead")
	}
	if r.AuthHeader == "" {
		r.AuthHeader = "Authorization"
	}
	if !validHeaderName(r.AuthHeader) {
		return fmt.Errorf("invalid auth header name %q", r.AuthHeader)
	}
	if r.CostPerRequest < 0 {
		return errors.New("cost per request cannot be negative")
	}
	if r.ExtraHeaders == nil {
		r.ExtraHeaders = map[string]string{}
	}
	for k := range r.ExtraHeaders {
		if !validHeaderName(k) {
			return fmt.Errorf("invalid header name %q", k)
		}
		switch http.CanonicalHeaderKey(k) {
		case "Host", "Content-Length", "Transfer-Encoding", "Connection":
			return fmt.Errorf("header %q cannot be overridden", k)
		}
	}
	return nil
}

func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c == '-' || c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			return false
		}
	}
	return true
}

const cols = `p.id::text, p.name, p.target_url, p.credential_id::text, coalesce(c.name,''), p.auth_header, p.auth_prefix,
	p.extra_headers, p.require_key, p.cost_per_request, p.description, p.enabled, p.created_at, p.updated_at`

func scan(row pgx.Row) (Route, error) {
	var r Route
	var hdr []byte
	err := row.Scan(&r.ID, &r.Name, &r.TargetURL, &r.CredentialID, &r.CredentialName, &r.AuthHeader, &r.AuthPrefix,
		&hdr, &r.RequireKey, &r.CostPerRequest, &r.Description, &r.Enabled, &r.CreatedAt, &r.UpdatedAt)
	r.ExtraHeaders = map[string]string{}
	if len(hdr) > 0 {
		_ = json.Unmarshal(hdr, &r.ExtraHeaders)
	}
	return r, err
}

// List returns every route ordered by name.
func (p *Router) List(ctx context.Context) ([]Route, error) {
	rows, err := p.store.Pool.Query(ctx, `SELECT `+cols+` FROM passthrough_routes p LEFT JOIN credentials c ON c.id = p.credential_id ORDER BY p.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Route{}
	for rows.Next() {
		r, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Get loads one route by id.
func (p *Router) Get(ctx context.Context, id string) (Route, error) {
	r, err := scan(p.store.Pool.QueryRow(ctx, `SELECT `+cols+` FROM passthrough_routes p LEFT JOIN credentials c ON c.id = p.credential_id WHERE p.id::text=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrNotFound
	}
	return r, err
}

// Save validates and inserts (empty ID) or updates a route, then reloads.
func (p *Router) Save(ctx context.Context, r *Route) error {
	if err := Validate(r); err != nil {
		return err
	}
	hdr, _ := json.Marshal(r.ExtraHeaders)
	var cred any
	if r.CredentialID != nil && *r.CredentialID != "" {
		cred = *r.CredentialID
	}
	var err error
	if r.ID == "" {
		err = p.store.Pool.QueryRow(ctx, `INSERT INTO passthrough_routes (name, target_url, credential_id, auth_header, auth_prefix,
			extra_headers, require_key, cost_per_request, description, enabled) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id::text`,
			r.Name, r.TargetURL, cred, r.AuthHeader, r.AuthPrefix, hdr, r.RequireKey, r.CostPerRequest, r.Description, r.Enabled).Scan(&r.ID)
	} else {
		var tag pgconn.CommandTag
		tag, err = p.store.Pool.Exec(ctx, `UPDATE passthrough_routes SET name=$2, target_url=$3, credential_id=$4, auth_header=$5,
			auth_prefix=$6, extra_headers=$7, require_key=$8, cost_per_request=$9, description=$10, enabled=$11, updated_at=now()
			WHERE id::text=$1`, r.ID, r.Name, r.TargetURL, cred, r.AuthHeader, r.AuthPrefix, hdr, r.RequireKey, r.CostPerRequest, r.Description, r.Enabled)
		if err == nil && tag.RowsAffected() == 0 {
			err = ErrNotFound
		}
	}
	if err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23505" {
			return ErrConflict
		}
		return err
	}
	return p.Reload(ctx)
}

// SetEnabled toggles a route.
func (p *Router) SetEnabled(ctx context.Context, id string, on bool) error {
	tag, err := p.store.Pool.Exec(ctx, `UPDATE passthrough_routes SET enabled=$2, updated_at=now() WHERE id::text=$1`, id, on)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return p.Reload(ctx)
}

// Delete removes a route.
func (p *Router) Delete(ctx context.Context, id string) error {
	if _, err := p.store.Pool.Exec(ctx, `DELETE FROM passthrough_routes WHERE id::text=$1`, id); err != nil {
		return err
	}
	return p.Reload(ctx)
}

// Call is one logged pass-through request.
type Call struct {
	At        time.Time
	RequestID string
	Route     string
	Method    string
	Path      string
	Status    string
	HTTP      int
	LatencyMs int
	Cost      float64
	KeyID     string
	KeyAlias  string
	Error     string
}

// RecentCalls lists the latest pass-through requests (optionally for one route).
func (p *Router) RecentCalls(ctx context.Context, route string, limit int) ([]Call, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	q := `SELECT created_at, request_id, route, coalesce(metadata->>'method',''), coalesce(metadata->>'path',''), status, http_status,
		latency_ms, cost, coalesce(key_id::text,''), key_alias, error
		FROM request_logs WHERE route LIKE 'passthrough/%'`
	args := []any{limit}
	if route != "" {
		q += ` AND route = $2`
		args = append(args, "passthrough/"+route)
	}
	rows, err := p.store.Pool.Query(ctx, q+` ORDER BY created_at DESC LIMIT $1`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Call{}
	for rows.Next() {
		var c Call
		if err := rows.Scan(&c.At, &c.RequestID, &c.Route, &c.Method, &c.Path, &c.Status, &c.HTTP, &c.LatencyMs, &c.Cost, &c.KeyID, &c.KeyAlias, &c.Error); err != nil {
			return nil, err
		}
		c.Route = strings.TrimPrefix(c.Route, "passthrough/")
		out = append(out, c)
	}
	return out, rows.Err()
}

// RouteStats are 24h counters per route name.
type RouteStats struct {
	Requests int
	Errors   int
	Cost     float64
}

// Stats24h aggregates the last 24 hours of pass-through traffic by route name.
func (p *Router) Stats24h(ctx context.Context) map[string]RouteStats {
	out := map[string]RouteStats{}
	rows, err := p.store.Pool.Query(ctx, `SELECT route, count(*)::int, count(*) FILTER (WHERE status <> 'success')::int, coalesce(sum(cost),0)
		FROM request_logs WHERE route LIKE 'passthrough/%' AND created_at > now() - interval '24 hours' GROUP BY route`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var s RouteStats
		if rows.Scan(&name, &s.Requests, &s.Errors, &s.Cost) == nil {
			out[strings.TrimPrefix(name, "passthrough/")] = s
		}
	}
	return out
}
