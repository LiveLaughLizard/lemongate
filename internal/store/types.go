package store

import "time"

// Budget fields shared by every spend-bearing entity.
type Budget struct {
	MaxBudget     *float64   `db:"max_budget" json:"max_budget"`
	BudgetPeriod  string     `db:"budget_period" json:"budget_period"`
	BudgetResetAt *time.Time `db:"budget_reset_at" json:"budget_reset_at"`
	Spend         float64    `db:"spend" json:"spend"`
}

// BudgetUsedPct returns spend as a percent of the budget, or -1 if unlimited.
func (b Budget) BudgetUsedPct() float64 {
	if b.MaxBudget == nil || *b.MaxBudget <= 0 {
		return -1
	}
	return b.Spend / *b.MaxBudget * 100
}

func (b Budget) OverBudget() bool { return b.MaxBudget != nil && b.Spend >= *b.MaxBudget }

type Limits struct {
	RPMLimit *int `db:"rpm_limit" json:"rpm_limit"`
	TPMLimit *int `db:"tpm_limit" json:"tpm_limit"`
}

type Organization struct {
	ID          string   `db:"id" json:"id"`
	Name        string   `db:"name" json:"name"`
	Description string   `db:"description" json:"description"`
	Models      []string `db:"models" json:"models"`
	Budget
	Limits
	Metadata  map[string]any `db:"metadata" json:"metadata"`
	Blocked   bool           `db:"blocked" json:"blocked"`
	CreatedAt time.Time      `db:"created_at" json:"created_at"`
	UpdatedAt time.Time      `db:"updated_at" json:"updated_at"`
	TeamCount int            `db:"team_count" json:"team_count"`
	UserCount int            `db:"user_count" json:"user_count"`
}

type User struct {
	ID           string   `db:"id" json:"id"`
	Email        string   `db:"email" json:"email"`
	Name         string   `db:"name" json:"name"`
	Role         string   `db:"role" json:"role"`
	PasswordHash string   `db:"password_hash" json:"-"`
	SSOSubject   *string  `db:"sso_subject" json:"sso_subject,omitempty"`
	OrgID        *string  `db:"org_id" json:"org_id"`
	Models       []string `db:"models" json:"models"`
	Budget
	Limits
	MaxParallel *int           `db:"max_parallel" json:"max_parallel"`
	Metadata    map[string]any `db:"metadata" json:"metadata"`
	Blocked     bool           `db:"blocked" json:"blocked"`
	LastLoginAt *time.Time     `db:"last_login_at" json:"last_login_at"`
	CreatedAt   time.Time      `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time      `db:"updated_at" json:"updated_at"`
	KeyCount    int            `db:"key_count" json:"key_count"`
	OrgName     *string        `db:"org_name" json:"org_name,omitempty"`
}

func (u User) DisplayName() string {
	if u.Name != "" {
		return u.Name
	}
	return u.Email
}

type Team struct {
	ID          string   `db:"id" json:"id"`
	Name        string   `db:"name" json:"name"`
	Description string   `db:"description" json:"description"`
	OrgID       *string  `db:"org_id" json:"org_id"`
	Models      []string `db:"models" json:"models"`
	Budget
	MemberMaxBudget *float64 `db:"member_max_budget" json:"member_max_budget"`
	Limits
	MaxParallel *int           `db:"max_parallel" json:"max_parallel"`
	Guardrails  []string       `db:"guardrails" json:"guardrails"`
	Policies    []string       `db:"policies" json:"policies"`
	MCPServers  []string       `db:"mcp_servers" json:"mcp_servers"`
	Metadata    map[string]any `db:"metadata" json:"metadata"`
	Blocked     bool           `db:"blocked" json:"blocked"`
	CreatedAt   time.Time      `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time      `db:"updated_at" json:"updated_at"`
	DeletedAt   *time.Time     `db:"deleted_at" json:"deleted_at,omitempty"`
	MemberCount int            `db:"member_count" json:"member_count"`
	KeyCount    int            `db:"key_count" json:"key_count"`
	OrgName     *string        `db:"org_name" json:"org_name,omitempty"`
}

type TeamMember struct {
	TeamID    string    `db:"team_id" json:"team_id"`
	UserID    string    `db:"user_id" json:"user_id"`
	Role      string    `db:"role" json:"role"`
	Spend     float64   `db:"spend" json:"spend"`
	MaxBudget *float64  `db:"max_budget" json:"max_budget"`
	JoinedAt  time.Time `db:"joined_at" json:"joined_at"`
	Email     string    `db:"email" json:"email"`
	Name      string    `db:"name" json:"name"`
	TeamName  string    `db:"team_name" json:"team_name"`
}

type Credential struct {
	ID          string    `db:"id" json:"id"`
	Name        string    `db:"name" json:"name"`
	Description string    `db:"description" json:"description"`
	SecretEnc   []byte    `db:"secret_enc" json:"-"`
	Hint        string    `db:"hint" json:"hint"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at" json:"updated_at"`
	UsageCount  int       `db:"usage_count" json:"usage_count"`
}

type Deployment struct {
	ID            string  `db:"id" json:"id"`
	Name          string  `db:"name" json:"name"`
	APIBase       string  `db:"api_base" json:"api_base"`
	UpstreamModel string  `db:"upstream_model" json:"upstream_model"`
	CredentialID  *string `db:"credential_id" json:"credential_id"`
	Mode          string  `db:"mode" json:"mode"`
	Weight        int     `db:"weight" json:"weight"`
	Limits
	MaxParallel     *int              `db:"max_parallel" json:"max_parallel"`
	TimeoutSeconds  int               `db:"timeout_seconds" json:"timeout_seconds"`
	ContextWindow   *int              `db:"context_window" json:"context_window"`
	MaxOutputTokens *int              `db:"max_output_tokens" json:"max_output_tokens"`
	InputCostPerM   float64           `db:"input_cost_per_m" json:"input_cost_per_m"`
	OutputCostPerM  float64           `db:"output_cost_per_m" json:"output_cost_per_m"`
	Description     string            `db:"description" json:"description"`
	Tags            []string          `db:"tags" json:"tags"`
	ExtraHeaders    map[string]string `db:"extra_headers" json:"extra_headers"`
	Enabled         bool              `db:"enabled" json:"enabled"`
	CreatedAt       time.Time         `db:"created_at" json:"created_at"`
	UpdatedAt       time.Time         `db:"updated_at" json:"updated_at"`
	CredentialName  *string           `db:"credential_name" json:"credential_name,omitempty"`

	// Not persisted: populated for deployments declared in the YAML config.
	FromConfig bool   `db:"-" json:"from_config"`
	APIKey     string `db:"-" json:"-"`
}

type Alias struct {
	Alias     string    `db:"alias" json:"alias"`
	Target    string    `db:"target" json:"target"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

type AccessGroup struct {
	Name        string    `db:"name" json:"name"`
	Description string    `db:"description" json:"description"`
	Models      []string  `db:"models" json:"models"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
}

type Fallback struct {
	Model   string   `db:"model" json:"model"`
	Kind    string   `db:"kind" json:"kind"`
	Targets []string `db:"targets" json:"targets"`
}

type Key struct {
	ID           string   `db:"id" json:"id"`
	KeyHash      string   `db:"key_hash" json:"-"`
	KeyHint      string   `db:"key_hint" json:"key_hint"`
	Alias        string   `db:"alias" json:"alias"`
	Scope        string   `db:"scope" json:"scope"`
	UserID       *string  `db:"user_id" json:"user_id"`
	TeamID       *string  `db:"team_id" json:"team_id"`
	Models       []string `db:"models" json:"models"`
	AccessGroups []string `db:"access_groups" json:"access_groups"`
	Budget
	Limits
	MaxParallel *int           `db:"max_parallel" json:"max_parallel"`
	ExpiresAt   *time.Time     `db:"expires_at" json:"expires_at"`
	Metadata    map[string]any `db:"metadata" json:"metadata"`
	Tags        []string       `db:"tags" json:"tags"`
	Guardrails  []string       `db:"guardrails" json:"guardrails"`
	Policies    []string       `db:"policies" json:"policies"`
	MCPServers  []string       `db:"mcp_servers" json:"mcp_servers"`
	Blocked     bool           `db:"blocked" json:"blocked"`
	LastUsedAt  *time.Time     `db:"last_used_at" json:"last_used_at"`
	CreatedBy   string         `db:"created_by" json:"created_by"`
	CreatedAt   time.Time      `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time      `db:"updated_at" json:"updated_at"`
	DeletedAt   *time.Time     `db:"deleted_at" json:"deleted_at,omitempty"`
	UserEmail   *string        `db:"user_email" json:"user_email,omitempty"`
	TeamName    *string        `db:"team_name" json:"team_name,omitempty"`
}

func (k Key) Expired() bool { return k.ExpiresAt != nil && time.Now().After(*k.ExpiresAt) }

func (k Key) Label() string {
	if k.Alias != "" {
		return k.Alias
	}
	return k.KeyHint
}

type EndUser struct {
	ID    string `db:"id" json:"id"`
	Alias string `db:"alias" json:"alias"`
	Budget
	Blocked     bool      `db:"blocked" json:"blocked"`
	FirstSeenAt time.Time `db:"first_seen_at" json:"first_seen_at"`
	LastSeenAt  time.Time `db:"last_seen_at" json:"last_seen_at"`
}

type Tag struct {
	Name        string `db:"name" json:"name"`
	Description string `db:"description" json:"description"`
	Color       string `db:"color" json:"color"`
	Budget
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

type BudgetPreset struct {
	ID           string   `db:"id" json:"id"`
	Name         string   `db:"name" json:"name"`
	MaxBudget    *float64 `db:"max_budget" json:"max_budget"`
	BudgetPeriod string   `db:"budget_period" json:"budget_period"`
	Limits
	MaxParallel *int      `db:"max_parallel" json:"max_parallel"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
}

type Session struct {
	TokenHash string    `db:"token_hash"`
	UserID    *string   `db:"user_id"`
	IsMaster  bool      `db:"is_master"`
	CSRFToken string    `db:"csrf_token"`
	CreatedAt time.Time `db:"created_at"`
	ExpiresAt time.Time `db:"expires_at"`
}

type AuditEntry struct {
	ID         int64          `db:"id" json:"id"`
	At         time.Time      `db:"at" json:"at"`
	ActorID    string         `db:"actor_id" json:"actor_id"`
	ActorLabel string         `db:"actor_label" json:"actor_label"`
	Action     string         `db:"action" json:"action"`
	EntityType string         `db:"entity_type" json:"entity_type"`
	EntityID   string         `db:"entity_id" json:"entity_id"`
	Summary    string         `db:"summary" json:"summary"`
	Before     map[string]any `db:"before" json:"before"`
	After      map[string]any `db:"after" json:"after"`
}
