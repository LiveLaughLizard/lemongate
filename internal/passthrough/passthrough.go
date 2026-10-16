// Package passthrough forwards admin-defined routes to arbitrary upstream URLs.
//
// A route named "tools" with target "http://10.0.0.5:9000/api" serves
// /pt/tools/<rest> by proxying to http://10.0.0.5:9000/api/<rest>?<query> with any
// method. The response is streamed back (flushed as it arrives) so server-sent
// events work. Client credentials, cookies and hop-by-hop headers are never
// forwarded; the route's credential, when set, is injected instead.
package passthrough

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"

	"lemongate/internal/auth"
	"lemongate/internal/metrics"
	"lemongate/internal/secret"
	"lemongate/internal/spend"
	"lemongate/internal/store"
)

// Router serves /pt/{name}/*.
type Router struct {
	store    *store.Store
	box      *secret.Box
	client   *http.Client
	resolver *auth.Resolver
	spend    *spend.Writer

	routes atomic.Pointer[map[string]*live]

	// Admit, when set, enforces budgets and rate limits for key-authenticated calls.
	Admit func(ctx context.Context, p *auth.Principal, tags []string) (release func(int), status int, err error)
}

// live is a loaded route with its decrypted credential.
type live struct {
	Route
	target *url.URL
	secret string
}

func New(s *store.Store, box *secret.Box, client *http.Client, resolver *auth.Resolver, sw *spend.Writer) *Router {
	if client == nil {
		client = http.DefaultClient
	}
	// Never follow redirects: relay them to the caller like any reverse proxy.
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	p := &Router{store: s, box: box, client: &c, resolver: resolver, spend: sw}
	empty := map[string]*live{}
	p.routes.Store(&empty)
	if s != nil {
		go p.refreshLoop()
	}
	return p
}

// RefreshInterval is how often routes are re-read so edits made through another
// replica (or credential rotations) take effect without a restart.
var RefreshInterval = 30 * time.Second

func (p *Router) refreshLoop() {
	t := time.NewTicker(RefreshInterval)
	defer t.Stop()
	for range t.C {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := p.Reload(ctx); err != nil {
			slog.Debug("pass-through refresh", "err", err)
		}
		cancel()
	}
}

// Reload re-reads routes and credentials from the database. Call it after edits.
func (p *Router) Reload(ctx context.Context) error {
	list, err := p.List(ctx)
	if err != nil {
		return err
	}
	secrets := map[string]string{}
	rows, err := p.store.Pool.Query(ctx, `SELECT c.id::text, c.secret_enc FROM credentials c
		WHERE c.id IN (SELECT credential_id FROM passthrough_routes WHERE credential_id IS NOT NULL)`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id string
		var enc []byte
		if rows.Scan(&id, &enc) == nil {
			s, err := p.box.OpenString(enc)
			if err != nil {
				slog.Warn("pass-through: cannot decrypt credential", "credential", id, "err", err)
				continue
			}
			secrets[id] = s
		}
	}
	rows.Close()
	m := make(map[string]*live, len(list))
	for _, r := range list {
		u, err := url.Parse(r.TargetURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			slog.Warn("pass-through: invalid target URL", "route", r.Name, "url", r.TargetURL)
			continue
		}
		l := &live{Route: r, target: u}
		if r.CredentialID != nil {
			l.secret = secrets[*r.CredentialID]
		}
		m[r.Name] = l
	}
	p.routes.Store(&m)
	return nil
}

// Mount registers the public /pt/{name}/* handler.
func (p *Router) Mount(r chi.Router) {
	r.HandleFunc("/pt/{name}", p.serve)
	r.HandleFunc("/pt/{name}/*", p.serve)
}

// Hop-by-hop headers (RFC 9110 §7.6.1) and headers that must never reach the upstream.
var hopHeaders = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func stripHop(h http.Header) {
	for _, f := range h.Values("Connection") {
		for _, name := range strings.Split(f, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopHeaders {
		h.Del(name)
	}
}

func (p *Router) serve(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	name := chi.URLParam(r, "name")
	rt := (*p.routes.Load())[name]
	if rt == nil || !rt.Enabled {
		writeError(w, http.StatusNotFound, "not_found", "route_not_found", "no pass-through route named "+name)
		return
	}
	var pr *auth.Principal
	if rt.RequireKey {
		var err error
		pr, err = p.resolver.ResolveKey(r.Context(), auth.BearerToken(r.Header))
		if err != nil {
			status, code := http.StatusUnauthorized, "invalid_api_key"
			if errors.Is(err, auth.ErrKeyBlocked) || errors.Is(err, auth.ErrKeyExpired) || errors.Is(err, auth.ErrOwnerBlocked) {
				status, code = http.StatusForbidden, "key_blocked"
			}
			writeError(w, status, "authentication_error", code, err.Error())
			return
		}
		if p.Admit != nil {
			var tags []string
			if pr.Key != nil {
				tags = pr.Key.Tags
			}
			release, status, err := p.Admit(r.Context(), pr, tags)
			if err != nil {
				writeError(w, status, "rate_limit_exceeded", "limit_exceeded", err.Error())
				return
			}
			defer release(0)
		}
	}

	rest := chi.URLParam(r, "*")
	target := *rt.target
	target.Path = joinPath(rt.target.Path, rest)
	if rest == "" && strings.HasSuffix(r.URL.Path, "/") && !strings.HasSuffix(target.Path, "/") {
		target.Path += "/"
	}
	target.RawPath = ""
	switch {
	case rt.target.RawQuery == "":
		target.RawQuery = r.URL.RawQuery
	case r.URL.RawQuery != "":
		target.RawQuery = rt.target.RawQuery + "&" + r.URL.RawQuery
	}

	out, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), r.Body)
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream_error", "bad_target", err.Error())
		return
	}
	if r.Body == nil || r.Body == http.NoBody {
		out.Body = nil
	}
	out.ContentLength = r.ContentLength
	out.Header = r.Header.Clone()
	stripHop(out.Header)
	out.Header.Del("Authorization")
	out.Header.Del("Cookie")
	if rt.RequireKey {
		out.Header.Del("x-api-key")
		out.Header.Del("api-key")
	}
	for k := range out.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-lemongate-") {
			out.Header.Del(k)
		}
	}
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		if prior := r.Header.Get("X-Forwarded-For"); prior != "" {
			ip = prior + ", " + ip
		}
		out.Header.Set("X-Forwarded-For", ip)
	}
	for k, v := range rt.ExtraHeaders {
		out.Header.Set(k, v)
	}
	if rt.secret != "" {
		out.Header.Set(rt.AuthHeader, rt.AuthPrefix+rt.secret)
	}
	reqID := "pt-" + auth.RandomString(20)
	w.Header().Set("x-lemongate-request-id", reqID)

	rec := spend.Record{RequestID: reqID, Route: "passthrough/" + rt.Name, KeyID: pr.KeyID(), UserID: pr.UserID(),
		TeamID: pr.TeamID(), OrgID: pr.OrgID(), APIBase: rt.target.Scheme + "://" + rt.target.Host,
		Metadata: map[string]any{"method": r.Method, "path": "/" + rest}}
	if pr != nil && pr.Key != nil {
		rec.KeyAlias = pr.Key.Alias
		rec.Tags = pr.Key.Tags
	}

	resp, err := p.client.Do(out)
	if err != nil {
		status := http.StatusBadGateway
		msg := "upstream request failed: " + err.Error()
		if errors.Is(err, context.Canceled) {
			status = 499
			msg = "client closed request"
		} else if errors.Is(err, context.DeadlineExceeded) {
			status = http.StatusGatewayTimeout
		}
		rec.Status, rec.HTTPStatus, rec.Error = "error", status, msg
		p.finish(rec, start)
		if status != 499 {
			writeError(w, status, "upstream_error", "upstream_unreachable", msg)
		}
		return
	}
	defer resp.Body.Close()

	stripHop(resp.Header)
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	n, copyErr := copyFlush(w, resp.Body)
	rec.HTTPStatus = resp.StatusCode
	rec.Metadata["bytes"] = n
	if resp.StatusCode < 400 {
		rec.Status = "success"
		rec.Cost = rt.CostPerRequest
	} else {
		rec.Status = "error"
		rec.Error = http.StatusText(resp.StatusCode)
	}
	if copyErr != nil && !errors.Is(copyErr, context.Canceled) {
		rec.Error = "stream interrupted: " + copyErr.Error()
	}
	p.finish(rec, start)
}

func (p *Router) finish(rec spend.Record, start time.Time) {
	rec.LatencyMs = int(time.Since(start).Milliseconds())
	metrics.Requests.WithLabelValues(rec.Route, "", rec.Status).Inc()
	metrics.Latency.WithLabelValues(rec.Route, "").Observe(float64(rec.LatencyMs) / 1000)
	if rec.Cost > 0 {
		metrics.Cost.WithLabelValues(rec.Route).Add(rec.Cost)
	}
	if p.spend != nil {
		p.spend.Submit(rec)
	}
}

// copyFlush streams src to w, flushing after every read so SSE and chunked
// responses reach the client without buffering.
func copyFlush(w http.ResponseWriter, src io.Reader) (int64, error) {
	rc := http.NewResponseController(w)
	buf := make([]byte, 32<<10)
	var total int64
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
			_ = rc.Flush()
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

func joinPath(base, rest string) string {
	if rest == "" {
		if base == "" {
			return "/"
		}
		return base
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(rest, "/")
}

func writeError(w http.ResponseWriter, status int, typ, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": msg, "type": typ, "code": code}})
}
