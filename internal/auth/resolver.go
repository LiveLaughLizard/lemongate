package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"

	"lemongate/internal/store"
)

var (
	ErrNoCredentials = errors.New("missing API key")
	ErrInvalidKey    = errors.New("invalid API key")
	ErrKeyBlocked    = errors.New("API key is blocked")
	ErrKeyExpired    = errors.New("API key has expired")
	ErrOwnerBlocked  = errors.New("the owner of this API key is blocked")
)

// Resolver turns bearer tokens into Principals, caching lookups briefly.
type Resolver struct {
	store     *store.Store
	masterKey string
	cache     *expirable.LRU[string, *Principal]
}

func NewResolver(s *store.Store, masterKey string) *Resolver {
	return &Resolver{store: s, masterKey: masterKey, cache: expirable.NewLRU[string, *Principal](10000, nil, 10*time.Second)}
}

// Invalidate drops all cached principals (call after admin mutations or spend flushes).
func (r *Resolver) Invalidate() { r.cache.Purge() }

// BearerToken extracts the API key from Authorization, x-api-key or api-key headers.
func BearerToken(h interface{ Get(string) string }) string {
	if v := h.Get("Authorization"); v != "" {
		if len(v) > 7 && strings.EqualFold(v[:7], "bearer ") {
			return strings.TrimSpace(v[7:])
		}
		return strings.TrimSpace(v)
	}
	if v := h.Get("x-api-key"); v != "" {
		return strings.TrimSpace(v)
	}
	return strings.TrimSpace(h.Get("api-key"))
}

func (r *Resolver) IsMaster(token string) bool {
	return token != "" && ConstantTimeEqual(token, r.masterKey)
}

// ResolveKey authenticates an API token (master key or virtual key).
func (r *Resolver) ResolveKey(ctx context.Context, token string) (*Principal, error) {
	if token == "" {
		return nil, ErrNoCredentials
	}
	if r.IsMaster(token) {
		return &Principal{Kind: "master", Role: RoleAdmin}, nil
	}
	hash := HashToken(token)
	if p, ok := r.cache.Get(hash); ok {
		return p, checkKey(p)
	}
	k, err := r.store.GetKeyByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrInvalidKey
		}
		return nil, err
	}
	p := &Principal{Kind: "key", Key: &k, Role: RoleMember}
	// Owner lookups fail closed: a key whose user or team is gone (or cannot be loaded)
	// must not run without that owner's blocks, budgets and model restrictions.
	if k.UserID != nil {
		u, err := r.store.GetUser(ctx, *k.UserID)
		if err != nil {
			return nil, ownerErr(err)
		}
		p.User = &u
		p.Role = u.Role
	}
	if k.TeamID != nil {
		t, err := r.store.GetTeam(ctx, *k.TeamID)
		if err != nil {
			return nil, ownerErr(err)
		}
		if t.DeletedAt != nil {
			return nil, ErrOwnerBlocked
		}
		p.Team = &t
		if t.OrgID != nil {
			o, err := r.store.GetOrg(ctx, *t.OrgID)
			if err != nil {
				return nil, ownerErr(err)
			}
			p.Org = &o
		}
	}
	if p.Org == nil && p.User != nil && p.User.OrgID != nil {
		o, err := r.store.GetOrg(ctx, *p.User.OrgID)
		if err != nil {
			return nil, ownerErr(err)
		}
		p.Org = &o
	}
	switch k.Scope {
	case "admin":
		p.Role = RoleAdmin
	case "inference":
		// Inference keys never carry management rights regardless of owner role.
		if p.Role == RoleAdmin || p.Role == RoleAdminViewer {
			p.Role = RoleMember
		}
	}
	r.cache.Add(hash, p)
	return p, checkKey(p)
}

func ownerErr(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return ErrOwnerBlocked
	}
	return err
}

func checkKey(p *Principal) error {
	if p.Key == nil {
		return nil
	}
	if p.Key.Blocked {
		return ErrKeyBlocked
	}
	if p.Key.Expired() {
		return ErrKeyExpired
	}
	if (p.User != nil && p.User.Blocked) || (p.Team != nil && p.Team.Blocked) || (p.Org != nil && p.Org.Blocked) {
		return ErrOwnerBlocked
	}
	return nil
}

// ResolveSession authenticates a browser session token.
func (r *Resolver) ResolveSession(ctx context.Context, token string) (*Principal, error) {
	if token == "" {
		return nil, ErrNoCredentials
	}
	sess, err := r.store.GetSession(ctx, HashToken(token))
	if err != nil {
		return nil, ErrInvalidKey
	}
	p := &Principal{Kind: "session", SessionCSRF: sess.CSRFToken}
	if sess.IsMaster {
		p.Role = RoleAdmin
		return p, nil
	}
	if sess.UserID == nil {
		return nil, ErrInvalidKey
	}
	u, err := r.store.GetUser(ctx, *sess.UserID)
	if err != nil || u.Blocked {
		return nil, ErrOwnerBlocked
	}
	p.User = &u
	p.Role = u.Role
	if u.OrgID != nil {
		if o, err := r.store.GetOrg(ctx, *u.OrgID); err == nil {
			p.Org = &o
		}
	}
	p.Memberships, _ = r.store.MembershipsForUser(ctx, u.ID)
	return p, nil
}

// NewSession creates a session row and returns the raw cookie token.
func (r *Resolver) NewSession(ctx context.Context, userID *string, master bool, ttl time.Duration, ip, ua string) (string, error) {
	token := RandomString(48)
	err := r.store.CreateSession(ctx, store.Session{
		TokenHash: HashToken(token), UserID: userID, IsMaster: master,
		CSRFToken: RandomString(32), ExpiresAt: time.Now().Add(ttl),
	}, ip, ua)
	return token, err
}

type ctxKey struct{}

func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

func FromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(ctxKey{}).(*Principal)
	return p
}
