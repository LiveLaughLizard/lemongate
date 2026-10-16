package mcpgw

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"lemongate/internal/store"
)

// Server is an upstream MCP server registration (table mcp_servers).
type Server struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	URL            string    `json:"url"`
	Transport      string    `json:"transport"` // http | sse
	CredentialID   *string   `json:"credential_id"`
	CredentialName string    `json:"credential_name,omitempty"`
	AuthHeader     string    `json:"auth_header"`
	AuthPrefix     string    `json:"auth_prefix"`
	Description    string    `json:"description"`
	AvailableToAll bool      `json:"available_to_all"`
	Enabled        bool      `json:"enabled"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`

	// staticSecret bypasses the credential store (tests).
	staticSecret string
}

// Transports supported for upstream connections.
const (
	TransportHTTP = "http"
	TransportSSE  = "sse"
)

// NamespaceSep separates server and tool in aggregated tool names.
const NamespaceSep = "__"

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// Validate normalises and checks a server definition.
func (s *Server) Validate() error {
	s.Name = strings.TrimSpace(s.Name)
	s.URL = strings.TrimSpace(s.URL)
	s.AuthHeader = strings.TrimSpace(s.AuthHeader)
	if !nameRe.MatchString(s.Name) {
		return errors.New("name must be 1-63 characters of lowercase letters, digits, '-' or '_' and start with a letter or digit")
	}
	if strings.Contains(s.Name, NamespaceSep) {
		return fmt.Errorf("name must not contain %q (it separates server and tool names)", NamespaceSep)
	}
	u, err := url.Parse(s.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("URL must be an absolute http(s) URL")
	}
	switch s.Transport {
	case "":
		s.Transport = TransportHTTP
	case TransportHTTP, TransportSSE:
	default:
		return errors.New("transport must be http or sse")
	}
	if s.AuthHeader == "" {
		s.AuthHeader = "Authorization"
	}
	if s.CredentialID != nil && *s.CredentialID == "" {
		s.CredentialID = nil
	}
	return nil
}

// ErrNotFound is returned when a server does not exist.
var ErrNotFound = store.ErrNotFound

// ErrConflict is returned when a server name is taken.
var ErrConflict = errors.New("a server with this name already exists")

const serverCols = `s.id::text, s.name, s.url, s.transport, s.credential_id::text, coalesce(c.name, ''), s.auth_header, s.auth_prefix,
	s.description, s.available_to_all, s.enabled, s.created_at, s.updated_at`

const serverFrom = ` FROM mcp_servers s LEFT JOIN credentials c ON c.id = s.credential_id`

func scanServer(row pgx.Row) (Server, error) {
	var s Server
	err := row.Scan(&s.ID, &s.Name, &s.URL, &s.Transport, &s.CredentialID, &s.CredentialName, &s.AuthHeader, &s.AuthPrefix,
		&s.Description, &s.AvailableToAll, &s.Enabled, &s.CreatedAt, &s.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, ErrNotFound
	}
	return s, err
}

func mapErr(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return ErrConflict
	}
	return err
}

// ListServers returns every registered server ordered by name.
func (g *Gateway) ListServers(ctx context.Context) ([]Server, error) {
	if g.store == nil {
		return g.snapshotConfigs(), nil
	}
	rows, err := g.store.Pool.Query(ctx, `SELECT `+serverCols+serverFrom+` ORDER BY s.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Server{}
	for rows.Next() {
		s, err := scanServer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// GetServer loads a server by id.
func (g *Gateway) GetServer(ctx context.Context, id string) (Server, error) {
	return scanServer(g.store.Pool.QueryRow(ctx, `SELECT `+serverCols+serverFrom+` WHERE s.id::text = $1`, id))
}

// GetServerByName loads a server by name.
func (g *Gateway) GetServerByName(ctx context.Context, name string) (Server, error) {
	return scanServer(g.store.Pool.QueryRow(ctx, `SELECT `+serverCols+serverFrom+` WHERE s.name = $1`, name))
}

// CreateServer validates and inserts a server, then reloads the gateway.
func (g *Gateway) CreateServer(ctx context.Context, s Server) (Server, error) {
	if err := s.Validate(); err != nil {
		return s, err
	}
	var id string
	err := g.store.Pool.QueryRow(ctx, `INSERT INTO mcp_servers (name, url, transport, credential_id, auth_header, auth_prefix, description, available_to_all, enabled)
		VALUES ($1,$2,$3,$4::uuid,$5,$6,$7,$8,$9) RETURNING id::text`,
		s.Name, s.URL, s.Transport, s.CredentialID, s.AuthHeader, s.AuthPrefix, s.Description, s.AvailableToAll, s.Enabled).Scan(&id)
	if err != nil {
		return s, mapErr(err)
	}
	g.reloadLogged(ctx)
	return g.GetServer(ctx, id)
}

// UpdateServer saves a server. Renames are propagated to key and team allow-lists.
func (g *Gateway) UpdateServer(ctx context.Context, s Server) error {
	if err := s.Validate(); err != nil {
		return err
	}
	tx, err := g.store.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var old string
	if err := tx.QueryRow(ctx, `SELECT name FROM mcp_servers WHERE id::text = $1 FOR UPDATE`, s.ID).Scan(&old); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE mcp_servers SET name=$2, url=$3, transport=$4, credential_id=$5::uuid, auth_header=$6, auth_prefix=$7,
		description=$8, available_to_all=$9, enabled=$10, updated_at=now() WHERE id::text=$1`,
		s.ID, s.Name, s.URL, s.Transport, s.CredentialID, s.AuthHeader, s.AuthPrefix, s.Description, s.AvailableToAll, s.Enabled); err != nil {
		return mapErr(err)
	}
	if old != s.Name {
		for _, tbl := range []string{"api_keys", "teams"} {
			if _, err := tx.Exec(ctx, `UPDATE `+tbl+` SET mcp_servers = array_replace(mcp_servers, $1, $2) WHERE $1 = ANY(mcp_servers)`, old, s.Name); err != nil {
				return err
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	g.reloadLogged(ctx)
	return nil
}

// SetEnabled toggles a server.
func (g *Gateway) SetEnabled(ctx context.Context, id string, enabled bool) error {
	tag, err := g.store.Pool.Exec(ctx, `UPDATE mcp_servers SET enabled=$2, updated_at=now() WHERE id::text=$1`, id, enabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	g.reloadLogged(ctx)
	return nil
}

// DeleteServer removes a server and drops it from key and team allow-lists.
func (g *Gateway) DeleteServer(ctx context.Context, id string) error {
	tx, err := g.store.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var name string
	if err := tx.QueryRow(ctx, `DELETE FROM mcp_servers WHERE id::text=$1 RETURNING name`, id).Scan(&name); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	for _, tbl := range []string{"api_keys", "teams"} {
		if _, err := tx.Exec(ctx, `UPDATE `+tbl+` SET mcp_servers = array_remove(mcp_servers, $1) WHERE $1 = ANY(mcp_servers)`, name); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	g.reloadLogged(ctx)
	return nil
}

// secretFor decrypts the credential attached to a server ("" when none).
func (g *Gateway) secretFor(ctx context.Context, s Server) (string, error) {
	if s.staticSecret != "" {
		return s.staticSecret, nil
	}
	if s.CredentialID == nil || g.store == nil {
		return "", nil
	}
	c, err := g.store.GetCredential(ctx, *s.CredentialID)
	if err != nil {
		return "", fmt.Errorf("load credential: %w", err)
	}
	if g.box == nil {
		return "", errors.New("no secret box configured")
	}
	plain, err := g.box.OpenString(c.SecretEnc)
	if err != nil {
		return "", fmt.Errorf("decrypt credential: %w", err)
	}
	return plain, nil
}

// --- tool call log ---

// Call is one logged tool invocation (table mcp_tool_calls).
type Call struct {
	ID         int64     `json:"id"`
	At         time.Time `json:"at"`
	Server     string    `json:"server"`
	Tool       string    `json:"tool"`
	KeyID      *string   `json:"key_id"`
	KeyLabel   string    `json:"key_label,omitempty"`
	UserID     *string   `json:"user_id"`
	UserEmail  string    `json:"user_email,omitempty"`
	DurationMS int       `json:"duration_ms"`
	OK         bool      `json:"ok"`
	Error      string    `json:"error"`
}

// CallFilter narrows ListCalls. Empty fields match everything.
type CallFilter struct {
	Server  string
	Servers []string // restrict to these servers (nil = no restriction)
	Tool    string
	Status  string // "", "ok", "error"
	KeyID   string
	UserID  string
	Since   time.Time
	Limit   int
}

// ListCalls returns recent tool calls, newest first.
func (g *Gateway) ListCalls(ctx context.Context, f CallFilter) ([]Call, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 100
	}
	var servers any
	if f.Servers != nil {
		servers = f.Servers
	}
	rows, err := g.store.Pool.Query(ctx, `SELECT c.id, c.at, c.server, c.tool, c.key_id::text, coalesce(nullif(k.alias, ''), k.key_hint, ''),
			c.user_id::text, coalesce(u.email, ''), c.duration_ms, c.ok, c.error
		FROM mcp_tool_calls c
		LEFT JOIN api_keys k ON k.id = c.key_id
		LEFT JOIN users u ON u.id = c.user_id
		WHERE ($1 = '' OR c.server = $1) AND ($2::text[] IS NULL OR c.server = ANY($2::text[]))
		  AND ($3 = '' OR c.tool ILIKE '%' || $3 || '%')
		  AND ($4 = '' OR ($4 = 'ok' AND c.ok) OR ($4 = 'error' AND NOT c.ok))
		  AND ($5 = '' OR c.key_id::text = $5) AND ($6 = '' OR c.user_id::text = $6)
		  AND c.at >= $7
		ORDER BY c.at DESC LIMIT $8`,
		f.Server, servers, f.Tool, f.Status, f.KeyID, f.UserID, f.Since, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Call{}
	for rows.Next() {
		var c Call
		if err := rows.Scan(&c.ID, &c.At, &c.Server, &c.Tool, &c.KeyID, &c.KeyLabel, &c.UserID, &c.UserEmail, &c.DurationMS, &c.OK, &c.Error); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CallStats summarises tool calls for one server.
type CallStats struct {
	Calls  int     `json:"calls"`
	Errors int     `json:"errors"`
	AvgMS  float64 `json:"avg_ms"`
}

// ErrorRate is the share of failed calls in percent.
func (c CallStats) ErrorRate() float64 {
	if c.Calls == 0 {
		return 0
	}
	return float64(c.Errors) * 100 / float64(c.Calls)
}

// Stats returns per-server call statistics since the given time.
func (g *Gateway) Stats(ctx context.Context, since time.Time) (map[string]CallStats, error) {
	rows, err := g.store.Pool.Query(ctx, `SELECT server, count(*)::int, count(*) FILTER (WHERE NOT ok)::int, coalesce(avg(duration_ms), 0)::float8
		FROM mcp_tool_calls WHERE at >= $1 GROUP BY server`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]CallStats{}
	for rows.Next() {
		var name string
		var s CallStats
		if err := rows.Scan(&name, &s.Calls, &s.Errors, &s.AvgMS); err != nil {
			return nil, err
		}
		out[name] = s
	}
	return out, rows.Err()
}

// ToolNames returns distinct tool names seen in the call log (for filters).
func (g *Gateway) ToolNames(ctx context.Context, server string) []string {
	rows, err := g.store.Pool.Query(ctx, `SELECT DISTINCT tool FROM mcp_tool_calls WHERE ($1 = '' OR server = $1) AND at > now() - interval '30 days' ORDER BY tool LIMIT 200`, server)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if rows.Scan(&s) == nil {
			out = append(out, s)
		}
	}
	return out
}

// pgxBatch inserts call records in one round trip.
type pgxBatch struct{ b pgx.Batch }

func (p *pgxBatch) add(r callRecord) {
	p.b.Queue(`INSERT INTO mcp_tool_calls (at, server, tool, key_id, user_id, duration_ms, ok, error)
		VALUES ($1, $2, $3, nullif($4, '')::uuid, nullif($5, '')::uuid, $6, $7, $8)`,
		r.at, r.server, r.tool, r.keyID, r.userID, int(r.dur.Milliseconds()), r.ok, r.err)
}

func (p *pgxBatch) send(ctx context.Context, s *store.Store) error {
	return s.Pool.SendBatch(ctx, &p.b).Close()
}
