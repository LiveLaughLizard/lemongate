package api

import "net/http"

// route is one API endpoint. The same table drives registration, access control,
// the OpenAPI document and the HTML reference.
type route struct {
	Method  string
	Path    string // relative to /api/v1, chi syntax ({id})
	Tag     string
	Summary string
	Desc    string
	Access  string // accessSelf | accessViewer | accessAdmin
	Query   []qparam
	Body    string // schema name of the JSON request body ("" = none)
	Resp    string // schema name of the response ("" = generic object); "list:X" = {data: [X]}
	Status  int    // success status (default 200)
	Example string // example JSON body for the reference page

	handler http.HandlerFunc
}

type qparam struct {
	Name, Type, Desc string
}

// tagInfo orders and describes the reference sections.
var tagInfo = []struct{ Name, Desc string }{
	{"Me", "The authenticated caller."},
	{"Keys", "Virtual API keys. Plaintext secrets are returned only when a key is created or regenerated."},
	{"Users", "Console users and their budgets and limits."},
	{"Teams", "Teams, their budgets, model access and members."},
	{"Organizations", "Organizations group teams and users."},
	{"Models", "Deployments (vLLM upstreams), aliases, access groups and fallbacks."},
	{"Credentials", "Encrypted upstream secrets. Secrets are write-only."},
	{"Budgets", "Tags, end users and reusable budget presets."},
	{"Extensions", "Guardrails, guardrail policies and presets, MCP servers and pass-through routes."},
	{"Alerts", "Alert channels (Slack, webhook, email), test sends and delivery history."},
	{"Settings", "Runtime settings."},
	{"Observability", "Usage analytics, request logs, deployment health and the audit log."},
}

func (h *H) routes() []route {
	keyFilters := []qparam{{"q", "string", "Search alias, key hint, owner email or team name"}, {"user_id", "string", "Owner user id"},
		{"team_id", "string", "Team id"}, {"deleted", "boolean", "List soft-deleted keys instead"}}
	rs := []route{
		{Method: "GET", Path: "/me", Tag: "Me", Summary: "Current principal", Desc: "Returns the role, user, team and key behind the bearer token.",
			Access: accessSelf, Resp: "Principal", handler: h.me},

		// keys
		{Method: "GET", Path: "/keys", Tag: "Keys", Summary: "List keys", Desc: "Admins see every key; members see their own keys and keys of their teams.",
			Access: accessSelf, Query: keyFilters, Resp: "list:Key", handler: h.listKeys},
		{Method: "POST", Path: "/keys", Tag: "Keys", Summary: "Create key", Desc: "Creates a key and returns its plaintext secret in `key` — it is shown only once. `expires_in` accepts durations such as `30d` or `12h`.",
			Access: accessSelf, Body: "KeyInput", Resp: "KeyCreated", Status: 201,
			Example: `{"alias": "support-bot", "models": ["llama-3.1-8b"], "max_budget": 25, "budget_period": "monthly", "expires_in": "90d"}`, handler: h.createKey},
		{Method: "GET", Path: "/keys/{id}", Tag: "Keys", Summary: "Get key", Access: accessSelf, Resp: "Key", handler: h.getKey},
		{Method: "PATCH", Path: "/keys/{id}", Tag: "Keys", Summary: "Update key", Desc: "Partial update: only the fields present are changed. Ownership and scope changes require admin.",
			Access: accessSelf, Body: "KeyInput", Resp: "Key", Example: `{"rpm_limit": 120, "tags": ["prod"]}`, handler: h.updateKey},
		{Method: "DELETE", Path: "/keys/{id}", Tag: "Keys", Summary: "Delete key", Desc: "Soft-deletes the key; it stops working immediately.", Access: accessSelf, Resp: "Deleted", handler: h.deleteKey},
		{Method: "POST", Path: "/keys/{id}/regenerate", Tag: "Keys", Summary: "Regenerate key", Desc: "Issues a new secret for the key; the old secret stops working.", Access: accessSelf, Resp: "KeyCreated", handler: h.regenerateKey},
		{Method: "POST", Path: "/keys/{id}/block", Tag: "Keys", Summary: "Block key", Access: accessSelf, Resp: "Key", handler: h.blockKey(true)},
		{Method: "POST", Path: "/keys/{id}/unblock", Tag: "Keys", Summary: "Unblock key", Access: accessSelf, Resp: "Key", handler: h.blockKey(false)},

		// users
		{Method: "GET", Path: "/users", Tag: "Users", Summary: "List users", Access: accessViewer,
			Query: []qparam{{"q", "string", "Search email or name"}, {"role", "string", "Filter by role"}}, Resp: "list:User", handler: h.listUsers},
		{Method: "POST", Path: "/users", Tag: "Users", Summary: "Create user", Desc: "`password` is optional (users can also sign in with SSO or an invite link).",
			Access: accessViewer, Body: "UserInput", Resp: "User", Status: 201, Example: `{"email": "ada@example.com", "name": "Ada", "role": "member", "max_budget": 50}`, handler: h.createUser},
		{Method: "GET", Path: "/users/{id}", Tag: "Users", Summary: "Get user", Access: accessViewer, Resp: "User", handler: h.getUser},
		{Method: "PATCH", Path: "/users/{id}", Tag: "Users", Summary: "Update user", Access: accessViewer, Body: "UserInput", Resp: "User", Example: `{"role": "admin_viewer"}`, handler: h.updateUser},
		{Method: "DELETE", Path: "/users/{id}", Tag: "Users", Summary: "Delete user", Access: accessViewer, Resp: "Deleted", handler: h.deleteUser},

		// teams
		{Method: "GET", Path: "/teams", Tag: "Teams", Summary: "List teams", Desc: "Members see only teams they belong to.", Access: accessSelf,
			Query: []qparam{{"q", "string", "Search by name"}, {"org_id", "string", "Organization id"}}, Resp: "list:Team", handler: h.listTeams},
		{Method: "POST", Path: "/teams", Tag: "Teams", Summary: "Create team", Access: accessViewer, Body: "Team", Resp: "Team", Status: 201,
			Example: `{"name": "ml-platform", "models": ["llama-3.1-8b"], "max_budget": 500, "budget_period": "monthly"}`, handler: h.createTeam},
		{Method: "GET", Path: "/teams/{id}", Tag: "Teams", Summary: "Get team", Access: accessSelf, Resp: "Team", handler: h.getTeam},
		{Method: "PATCH", Path: "/teams/{id}", Tag: "Teams", Summary: "Update team", Access: accessViewer, Body: "Team", Resp: "Team", Example: `{"tpm_limit": 200000}`, handler: h.updateTeam},
		{Method: "DELETE", Path: "/teams/{id}", Tag: "Teams", Summary: "Delete team", Desc: "Soft-deletes the team.", Access: accessViewer, Resp: "Deleted", handler: h.deleteTeam},
		{Method: "GET", Path: "/teams/{id}/members", Tag: "Teams", Summary: "List team members", Access: accessSelf, Resp: "list:TeamMember", handler: h.listMembers},
		{Method: "POST", Path: "/teams/{id}/members", Tag: "Teams", Summary: "Add or update member", Desc: "Team admins and admins only. `role` is `team_admin` or `team_member`.",
			Access: accessSelf, Body: "MemberInput", Resp: "TeamMember", Example: `{"user_id": "…", "role": "team_member", "max_budget": 20}`, handler: h.addMember},
		{Method: "DELETE", Path: "/teams/{id}/members/{user_id}", Tag: "Teams", Summary: "Remove member", Access: accessSelf, Resp: "Deleted", handler: h.removeMember},

		// orgs
		{Method: "GET", Path: "/organizations", Tag: "Organizations", Summary: "List organizations", Access: accessViewer, Resp: "list:Organization", handler: h.listOrgs},
		{Method: "POST", Path: "/organizations", Tag: "Organizations", Summary: "Create organization", Access: accessViewer, Body: "Organization", Resp: "Organization", Status: 201,
			Example: `{"name": "research", "max_budget": 2000, "budget_period": "monthly"}`, handler: h.createOrg},
		{Method: "GET", Path: "/organizations/{id}", Tag: "Organizations", Summary: "Get organization", Access: accessViewer, Resp: "Organization", handler: h.getOrg},
		{Method: "PATCH", Path: "/organizations/{id}", Tag: "Organizations", Summary: "Update organization", Access: accessViewer, Body: "Organization", Resp: "Organization", handler: h.updateOrg},
		{Method: "DELETE", Path: "/organizations/{id}", Tag: "Organizations", Summary: "Delete organization", Access: accessViewer, Resp: "Deleted", handler: h.deleteOrg},

		// models
		{Method: "GET", Path: "/deployments", Tag: "Models", Summary: "List deployments", Desc: "Database-managed deployments (models declared in the YAML config are read-only and not listed here; see /health).",
			Access: accessViewer, Resp: "list:Deployment", handler: h.listDeployments},
		{Method: "POST", Path: "/deployments", Tag: "Models", Summary: "Create deployment", Desc: "Deployments sharing a `name` form one model group.", Access: accessViewer, Body: "Deployment", Resp: "Deployment", Status: 201,
			Example: `{"name": "llama-3.1-8b", "api_base": "http://vllm-1:8000/v1", "upstream_model": "meta-llama/Llama-3.1-8B-Instruct", "input_cost_per_m": 0.1, "output_cost_per_m": 0.2}`, handler: h.createDeployment},
		{Method: "GET", Path: "/deployments/{id}", Tag: "Models", Summary: "Get deployment", Access: accessViewer, Resp: "Deployment", handler: h.getDeployment},
		{Method: "PATCH", Path: "/deployments/{id}", Tag: "Models", Summary: "Update deployment", Access: accessViewer, Body: "Deployment", Resp: "Deployment", Example: `{"weight": 3, "enabled": true}`, handler: h.updateDeployment},
		{Method: "DELETE", Path: "/deployments/{id}", Tag: "Models", Summary: "Delete deployment", Access: accessViewer, Resp: "Deleted", handler: h.deleteDeployment},
		{Method: "GET", Path: "/aliases", Tag: "Models", Summary: "List aliases", Access: accessViewer, Resp: "list:Alias", handler: h.listAliases},
		{Method: "POST", Path: "/aliases", Tag: "Models", Summary: "Create or update alias", Access: accessViewer, Body: "Alias", Resp: "Alias", Example: `{"alias": "default", "target": "llama-3.1-8b"}`, handler: h.upsertAlias},
		{Method: "DELETE", Path: "/aliases/{alias}", Tag: "Models", Summary: "Delete alias", Access: accessViewer, Resp: "Deleted", handler: h.deleteAlias},
		{Method: "GET", Path: "/access-groups", Tag: "Models", Summary: "List access groups", Access: accessViewer, Resp: "list:AccessGroup", handler: h.listAccessGroups},
		{Method: "POST", Path: "/access-groups", Tag: "Models", Summary: "Create or replace access group", Access: accessViewer, Body: "AccessGroup", Resp: "AccessGroup",
			Example: `{"name": "small-models", "models": ["llama-3.1-8b", "bge-m3"]}`, handler: h.upsertAccessGroup},
		{Method: "PATCH", Path: "/access-groups/{name}", Tag: "Models", Summary: "Update access group", Access: accessViewer, Body: "AccessGroup", Resp: "AccessGroup", handler: h.updateAccessGroup},
		{Method: "DELETE", Path: "/access-groups/{name}", Tag: "Models", Summary: "Delete access group", Access: accessViewer, Resp: "Deleted", handler: h.deleteAccessGroup},
		{Method: "GET", Path: "/fallbacks", Tag: "Models", Summary: "List fallbacks", Access: accessViewer, Resp: "list:Fallback", handler: h.listFallbacks},
		{Method: "POST", Path: "/fallbacks", Tag: "Models", Summary: "Create or replace fallback", Desc: "`kind` is `general` (errors) or `context` (context-window overflow).",
			Access: accessViewer, Body: "Fallback", Resp: "Fallback", Example: `{"model": "llama-3.1-70b", "kind": "general", "targets": ["llama-3.1-8b"]}`, handler: h.upsertFallback},
		{Method: "DELETE", Path: "/fallbacks/{model}", Tag: "Models", Summary: "Delete fallback", Access: accessViewer,
			Query: []qparam{{"kind", "string", "general (default) or context"}}, Resp: "Deleted", handler: h.deleteFallback},

		// credentials
		{Method: "GET", Path: "/credentials", Tag: "Credentials", Summary: "List credentials", Access: accessViewer, Resp: "list:Credential", handler: h.listCredentials},
		{Method: "POST", Path: "/credentials", Tag: "Credentials", Summary: "Create credential", Desc: "The secret is encrypted at rest and never returned; only a short hint is.",
			Access: accessViewer, Body: "CredentialInput", Resp: "Credential", Status: 201, Example: `{"name": "vllm-prod", "secret": "token-abc123"}`, handler: h.createCredential},
		{Method: "GET", Path: "/credentials/{id}", Tag: "Credentials", Summary: "Get credential", Access: accessViewer, Resp: "Credential", handler: h.getCredential},
		{Method: "PATCH", Path: "/credentials/{id}", Tag: "Credentials", Summary: "Update credential", Desc: "Omit `secret` to keep the current one.", Access: accessViewer, Body: "CredentialInput", Resp: "Credential", handler: h.updateCredential},
		{Method: "DELETE", Path: "/credentials/{id}", Tag: "Credentials", Summary: "Delete credential", Access: accessViewer, Resp: "Deleted", handler: h.deleteCredential},

		// budgets
		{Method: "GET", Path: "/tags", Tag: "Budgets", Summary: "List tags", Access: accessViewer, Resp: "list:Tag", handler: h.listTags},
		{Method: "POST", Path: "/tags", Tag: "Budgets", Summary: "Create tag", Access: accessViewer, Body: "Tag", Resp: "Tag", Status: 201, Example: `{"name": "billing-dept", "max_budget": 100, "budget_period": "monthly"}`, handler: h.createTag},
		{Method: "GET", Path: "/tags/{name}", Tag: "Budgets", Summary: "Get tag", Access: accessViewer, Resp: "Tag", handler: h.getTag},
		{Method: "PATCH", Path: "/tags/{name}", Tag: "Budgets", Summary: "Update tag", Access: accessViewer, Body: "Tag", Resp: "Tag", handler: h.updateTag},
		{Method: "DELETE", Path: "/tags/{name}", Tag: "Budgets", Summary: "Delete tag", Access: accessViewer, Resp: "Deleted", handler: h.deleteTag},
		{Method: "GET", Path: "/end-users", Tag: "Budgets", Summary: "List end users", Access: accessViewer, Query: []qparam{{"q", "string", "Search id or alias"}}, Resp: "list:EndUser", handler: h.listEndUsers},
		{Method: "POST", Path: "/end-users", Tag: "Budgets", Summary: "Create end user", Desc: "End users are the `user` field of requests; they are also created automatically on first use.",
			Access: accessViewer, Body: "EndUser", Resp: "EndUser", Status: 201, Example: `{"id": "customer-42", "max_budget": 5, "budget_period": "daily"}`, handler: h.createEndUser},
		{Method: "GET", Path: "/end-users/{id}", Tag: "Budgets", Summary: "Get end user", Access: accessViewer, Resp: "EndUser", handler: h.getEndUser},
		{Method: "PATCH", Path: "/end-users/{id}", Tag: "Budgets", Summary: "Update end user", Access: accessViewer, Body: "EndUser", Resp: "EndUser", handler: h.updateEndUser},
		{Method: "DELETE", Path: "/end-users/{id}", Tag: "Budgets", Summary: "Delete end user", Access: accessViewer, Resp: "Deleted", handler: h.deleteEndUser},
		{Method: "GET", Path: "/budget-presets", Tag: "Budgets", Summary: "List budget presets", Access: accessViewer, Resp: "list:BudgetPreset", handler: h.listPresets},
		{Method: "POST", Path: "/budget-presets", Tag: "Budgets", Summary: "Create budget preset", Access: accessViewer, Body: "BudgetPreset", Resp: "BudgetPreset", Status: 201,
			Example: `{"name": "starter", "max_budget": 10, "budget_period": "monthly", "rpm_limit": 60}`, handler: h.createPreset},
		{Method: "GET", Path: "/budget-presets/{id}", Tag: "Budgets", Summary: "Get budget preset", Access: accessViewer, Resp: "BudgetPreset", handler: h.getPreset},
		{Method: "PATCH", Path: "/budget-presets/{id}", Tag: "Budgets", Summary: "Update budget preset", Access: accessViewer, Body: "BudgetPreset", Resp: "BudgetPreset", handler: h.updatePreset},
		{Method: "DELETE", Path: "/budget-presets/{id}", Tag: "Budgets", Summary: "Delete budget preset", Access: accessViewer, Resp: "Deleted", handler: h.deletePreset},
	}
	rs = append(rs, h.rawRoutes()...)
	rs = append(rs, h.guardrailRoutes()...)
	rs = append(rs, h.alertRoutes()...)
	rs = append(rs, h.opsRoutes()...)
	return rs
}
