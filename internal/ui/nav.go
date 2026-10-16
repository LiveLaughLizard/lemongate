package ui

import "lemongate/internal/auth"

type NavItem struct {
	Key   string
	Label string
	Icon  string
	Href  string
	// Visibility: "all" (any signed-in user), "viewer" (admin or admin_viewer), "admin".
	Access string
}

type NavGroup struct {
	Label string
	Items []NavItem
}

var navGroups = []NavGroup{
	{"", []NavItem{
		{"dashboard", "Dashboard", icon("layout-dashboard"), "/ui", "all"},
		{"playground", "Playground", icon("message-square-text"), "/ui/playground", "all"},
		{"hub", "Model hub", icon("boxes"), "/ui/hub", "all"},
	}},
	{"Gateway", []NavItem{
		{"models", "Models", icon("server"), "/ui/models", "viewer"},
		{"keys", "API keys", icon("key-round"), "/ui/keys", "all"},
		{"usage", "Usage", icon("chart-column"), "/ui/usage", "all"},
		{"logs", "Request logs", icon("scroll-text"), "/ui/logs", "all"},
	}},
	{"Access", []NavItem{
		{"teams", "Teams", icon("users"), "/ui/teams", "all"},
		{"orgs", "Organizations", icon("building-2"), "/ui/orgs", "viewer"},
		{"users", "Users", icon("user-round-cog"), "/ui/users", "viewer"},
		{"endusers", "End users", icon("contact"), "/ui/end-users", "viewer"},
		{"budgets", "Budgets", icon("wallet"), "/ui/budgets", "viewer"},
		{"tags", "Tags", icon("tags"), "/ui/tags", "viewer"},
	}},
	{"Extensions", []NavItem{
		{"guardrails", "Guardrails", icon("shield-check"), "/ui/guardrails", "viewer"},
		{"mcp", "MCP servers", icon("plug-zap"), "/ui/mcp", "all"},
		{"passthrough", "Pass-through", icon("route"), "/ui/passthrough", "viewer"},
		{"cache", "Cache", icon("database-zap"), "/ui/cache", "viewer"},
	}},
	{"Administration", []NavItem{
		{"alerts", "Alerts", icon("bell-ring"), "/ui/alerts", "viewer"},
		{"credentials", "Credentials", icon("lock-keyhole"), "/ui/credentials", "viewer"},
		{"settings", "Settings", icon("settings"), "/ui/settings", "viewer"},
		{"audit", "Audit log", icon("history"), "/ui/audit", "viewer"},
	}},
}

// NavFor filters navigation to what the principal may see.
func NavFor(p *auth.Principal) []NavGroup {
	var out []NavGroup
	for _, g := range navGroups {
		ng := NavGroup{Label: g.Label}
		for _, it := range g.Items {
			switch it.Access {
			case "admin":
				if !p.IsAdmin() {
					continue
				}
			case "viewer":
				if !p.CanViewAll() {
					continue
				}
			}
			ng.Items = append(ng.Items, it)
		}
		if len(ng.Items) > 0 {
			out = append(out, ng)
		}
	}
	return out
}

// icon marks a Lucide icon name so the asset build bundles it.
func icon(name string) string { return name }
