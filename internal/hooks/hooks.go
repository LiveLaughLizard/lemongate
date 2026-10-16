// Package hooks defines the extension points the gateway calls into. Optional modules
// (guardrails, cache, alerting) implement these without importing the gateway.
package hooks

import (
	"context"
	"time"

	"lemongate/internal/auth"
)

// CallInfo describes an in-flight model call.
type CallInfo struct {
	RequestID string
	Route     string // e.g. "chat/completions"
	Model     string // public model group name (after alias resolution)
	Principal *auth.Principal
	Stream    bool
	// Guardrails or policies explicitly requested by the caller (request body "guardrails" field).
	RequestedGuardrails []string
	// Request is the request body as forwarded upstream (gateway-only fields removed).
	// Post-call checks use it for conversation context; treat it as read-only.
	Request map[string]any
}

// GuardrailBlock is returned by guardrails to reject a request/response.
type GuardrailBlock struct {
	Guardrail string
	Reason    string
}

func (g *GuardrailBlock) Error() string {
	return "blocked by guardrail " + g.Guardrail + ": " + g.Reason
}

// Guardrails inspects (and may rewrite) request and response bodies.
// Body is the decoded JSON object; implementations mutate it in place to mask content.
type Guardrails interface {
	PreCall(ctx context.Context, info CallInfo, body map[string]any) error
	PostCall(ctx context.Context, info CallInfo, body map[string]any) error
	// PostStream is called with the assembled text of a streamed response; it can only log.
	PostStream(ctx context.Context, info CallInfo, text string)
}

// Cache stores full non-streaming responses.
type Cache interface {
	Key(info CallInfo, body map[string]any) (string, bool) // false = not cacheable
	Get(key string) ([]byte, bool)
	Set(key string, value []byte, ttl time.Duration)
}

// Event is something worth alerting on.
type Event struct {
	Kind      string // budget_threshold | key_expiring | deployment_down | deployment_up | error_rate | slow_response | daily_report | test
	Severity  string // info | warning | critical
	Title     string
	Body      string
	DedupeKey string
	Fields    map[string]string
}

type Alerter interface {
	Emit(ev Event)
}

type nopAlerter struct{}

func (nopAlerter) Emit(Event) {}

var NopAlerter Alerter = nopAlerter{}
