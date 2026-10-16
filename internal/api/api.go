// Package api is the JSON management API under /api/v1.
//
// Every route is declared once in a route table (see routes.go) that drives
// registration, access control, the OpenAPI document (/api/openapi.json) and the
// HTML reference (/api/docs).
//
// Authentication is a Bearer token: the master key, or a virtual key whose scope is
// "admin" (full access) or "management" (the owning user's own console permissions).
// Inference-scope keys are rejected with 403.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"lemongate/internal/auth"
	"lemongate/internal/guardrails"
	"lemongate/internal/store"
	"lemongate/internal/ui"
)

// maxBody caps JSON request bodies.
const maxBody = 1 << 20

// Hooks lets the application refresh optional engines after the API mutates their
// tables. Every field is optional.
type Hooks struct {
	ReloadGuardrails  func(context.Context) error
	ReloadMCP         func(context.Context) error
	ReloadPassthrough func(context.Context) error
	// Guardrails serves the guardrail policy, preset and catalog endpoints.
	Guardrails *guardrails.Engine
}

var hooks atomic.Pointer[Hooks]

// SetHooks installs reload hooks (safe to call before or after Mount).
func SetHooks(h Hooks) { hooks.Store(&h) }

func runHook(ctx context.Context, name string, pick func(*Hooks) func(context.Context) error) {
	h := hooks.Load()
	if h == nil {
		return
	}
	if fn := pick(h); fn != nil {
		if err := fn(context.WithoutCancel(ctx)); err != nil {
			slog.Error("api reload hook", "hook", name, "err", err)
		}
	}
}

// H holds the API handlers.
type H struct{ d *ui.Deps }

// Mount registers /api/v1 routes, /api/openapi.json and /api/docs.
func Mount(r chi.Router, d *ui.Deps) {
	h := &H{d: d}
	table := h.routes()
	spec := buildOpenAPI(table, d.Cfg.BaseURL)
	specJSON, _ := json.MarshalIndent(spec, "", "  ")
	r.Get("/api/openapi.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_, _ = w.Write(specJSON)
	})
	r.Get("/api/docs", h.docsHandler(table))
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(h.authenticate)
		for _, rt := range table {
			r.With(access(rt.Access)).Method(rt.Method, rt.Path, rt.handler)
		}
		r.NotFound(func(w http.ResponseWriter, _ *http.Request) {
			fail(w, http.StatusNotFound, "not_found", "no such API endpoint")
		})
		r.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) {
			fail(w, http.StatusMethodNotAllowed, "invalid_request_error", "method not allowed")
		})
	})
}

// --- authentication & authorization ---

func (h *H) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, status, msg := h.resolve(r.Context(), auth.BearerToken(r.Header))
		if p == nil {
			typ := "authentication_error"
			if status == http.StatusForbidden {
				typ = "permission_error"
			}
			if status == http.StatusUnauthorized {
				w.Header().Set("WWW-Authenticate", `Bearer realm="lemongate"`)
			}
			fail(w, status, typ, msg)
			return
		}
		next.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), p)))
	})
}

// resolve authenticates a token and applies the key-scope rules. On failure it returns
// a nil principal plus the HTTP status and message.
func (h *H) resolve(ctx context.Context, token string) (*auth.Principal, int, string) {
	if token == "" {
		return nil, http.StatusUnauthorized, "missing API key: send Authorization: Bearer <key>"
	}
	p, err := h.d.Resolver.ResolveKey(ctx, token)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrKeyBlocked), errors.Is(err, auth.ErrOwnerBlocked):
			return nil, http.StatusForbidden, err.Error()
		case errors.Is(err, auth.ErrInvalidKey), errors.Is(err, auth.ErrKeyExpired), errors.Is(err, auth.ErrNoCredentials):
			return nil, http.StatusUnauthorized, err.Error()
		}
		return nil, http.StatusInternalServerError, "could not verify API key"
	}
	if status, msg := scopeCheck(p); status != 0 {
		return nil, status, msg
	}
	if p.Kind == "key" {
		// Copy: resolved principals are cached and shared with the data plane.
		cp := *p
		p = &cp
		if p.User != nil && p.Key.Scope != "admin" {
			p.Memberships, _ = h.d.Store.MembershipsForUser(ctx, p.User.ID)
		}
	}
	return p, 0, ""
}

// scopeCheck enforces which principals may use the management API at all.
func scopeCheck(p *auth.Principal) (int, string) {
	if p == nil {
		return http.StatusUnauthorized, "invalid API key"
	}
	if p.Kind == "master" {
		return 0, ""
	}
	if p.Key == nil {
		return http.StatusForbidden, "this credential cannot use the management API"
	}
	switch p.Key.Scope {
	case "admin":
		return 0, ""
	case "management":
		if p.User == nil && p.Team == nil {
			return http.StatusForbidden, "management keys must belong to a user or team"
		}
		return 0, ""
	}
	return http.StatusForbidden, "this key has inference scope; create a key with management or admin scope to use the management API"
}

// Access levels of a route.
const (
	accessSelf   = "self"   // any authenticated principal; handler scopes the data
	accessViewer = "viewer" // GET: admins and read-only admins
	accessAdmin  = "admin"  // full admins only
)

// allowed decides route-level access for a principal and method.
func allowed(p *auth.Principal, level, method string) (bool, string) {
	write := method != http.MethodGet && method != http.MethodHead
	if write && p.ReadOnly() {
		return false, "your role is read-only"
	}
	switch level {
	case accessSelf:
		return true, ""
	case accessViewer:
		if write {
			if !p.IsAdmin() {
				return false, "admin role required"
			}
			return true, ""
		}
		if !p.CanViewAll() {
			return false, "admin or admin viewer role required"
		}
		return true, ""
	default:
		if !p.IsAdmin() {
			return false, "admin role required"
		}
		return true, ""
	}
}

func access(level string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ok, msg := allowed(auth.FromContext(r.Context()), level, r.Method); !ok {
				fail(w, http.StatusForbidden, "permission_error", msg)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// --- response helpers ---

type apiError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func fail(w http.ResponseWriter, status int, typ, msg string) {
	writeJSON(w, status, map[string]apiError{"error": {Message: msg, Type: typ}})
}

func badRequest(w http.ResponseWriter, format string, args ...any) {
	fail(w, http.StatusBadRequest, "invalid_request_error", fmt.Sprintf(format, args...))
}

func forbidden(w http.ResponseWriter, msg string) {
	fail(w, http.StatusForbidden, "permission_error", msg)
}

func notFound(w http.ResponseWriter, what string) {
	fail(w, http.StatusNotFound, "not_found", what+" not found")
}

// storeErr maps store/database errors to API errors.
func storeErr(w http.ResponseWriter, err error, what string) {
	err = dbErr(err)
	var ie inputErr
	switch {
	case errors.As(err, &ie):
		badRequest(w, "%s", ie.msg)
	case errors.Is(err, store.ErrNotFound):
		notFound(w, what)
	case errors.Is(err, store.ErrConflict):
		fail(w, http.StatusConflict, "conflict", what+" already exists")
	default:
		slog.Error("api", "entity", what, "err", err)
		fail(w, http.StatusInternalServerError, "internal_error", err.Error())
	}
}

type inputErr struct{ msg string }

func (e inputErr) Error() string { return e.msg }

// dbErr classifies raw database errors (unique, foreign-key and type violations).
func dbErr(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		switch pg.Code {
		case "23505":
			return store.ErrConflict
		case "23503":
			return inputErr{"a referenced record does not exist"}
		case "22P02", "23502", "23514":
			return inputErr{"invalid value: " + pg.Message}
		}
	}
	return err
}

func isDBError(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg)
}

// decode reads a JSON body onto v (which may be pre-populated for partial updates).
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		badRequest(w, "request body too large or unreadable")
		return false
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		badRequest(w, "request body must be a JSON object")
		return false
	}
	if err := json.Unmarshal(body, v); err != nil {
		badRequest(w, "invalid JSON: %v", err)
		return false
	}
	return true
}

// list wraps collections uniformly.
func list[T any](items []T) map[string]any {
	if items == nil {
		items = []T{}
	}
	return map[string]any{"data": items, "count": len(items)}
}

func principal(r *http.Request) *auth.Principal { return auth.FromContext(r.Context()) }

func param(r *http.Request, k string) string { return chi.URLParam(r, k) }
