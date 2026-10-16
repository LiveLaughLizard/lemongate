// Package config loads process configuration from environment variables and an
// optional YAML file. Runtime-tunable settings live in the database (see package settings).
package config

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen       string
	BaseURL      string
	DatabaseURL  string
	MasterKey    string
	MetricsToken string // LEMONGATE_METRICS_TOKEN: static scrape token; forces /metrics auth
	SecretKey    string
	ConfigPath   string
	DevMode      bool
	SessionHours int

	OIDC OIDCConfig
	SMTP SMTPConfig

	File FileConfig
}

type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	Scopes       []string
	RoleClaim    string
	AdminValues  []string
	DefaultRole  string
	DefaultTeam  string
	ButtonLabel  string
}

func (o OIDCConfig) Enabled() bool { return o.Issuer != "" && o.ClientID != "" }

type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	StartTLS bool
}

func (s SMTPConfig) Enabled() bool { return s.Host != "" && s.From != "" }

// FileConfig is the YAML file shape. Models declared here are read-only in the UI.
type FileConfig struct {
	Models           []FileModel         `yaml:"models"`
	Aliases          map[string]string   `yaml:"aliases"`
	Fallbacks        map[string][]string `yaml:"fallbacks"`
	ContextFallbacks map[string][]string `yaml:"context_fallbacks"`
	AccessGroups     map[string][]string `yaml:"access_groups"`
	Settings         map[string]any      `yaml:"settings"`
}

type FileModel struct {
	Name            string            `yaml:"name"`
	APIBase         string            `yaml:"api_base"`
	UpstreamModel   string            `yaml:"upstream_model"`
	APIKey          string            `yaml:"api_key"`
	Mode            string            `yaml:"mode"`
	Weight          int               `yaml:"weight"`
	RPMLimit        *int              `yaml:"rpm_limit"`
	TPMLimit        *int              `yaml:"tpm_limit"`
	MaxParallel     *int              `yaml:"max_parallel"`
	TimeoutSeconds  int               `yaml:"timeout_seconds"`
	ContextWindow   *int              `yaml:"context_window"`
	MaxOutputTokens *int              `yaml:"max_output_tokens"`
	InputCostPerM   float64           `yaml:"input_cost_per_m"`
	OutputCostPerM  float64           `yaml:"output_cost_per_m"`
	Description     string            `yaml:"description"`
	Tags            []string          `yaml:"tags"`
	ExtraHeaders    map[string]string `yaml:"extra_headers"`
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envList(key string, def []string) []string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func Load() (*Config, error) {
	c := &Config{
		Listen:       env("LEMONGATE_LISTEN", ":4000"),
		BaseURL:      strings.TrimRight(env("LEMONGATE_BASE_URL", "http://localhost:4000"), "/"),
		DatabaseURL:  env("DATABASE_URL", ""),
		MasterKey:    env("LEMONGATE_MASTER_KEY", ""),
		MetricsToken: env("LEMONGATE_METRICS_TOKEN", ""),
		SecretKey:    env("LEMONGATE_SECRET_KEY", ""),
		ConfigPath:   env("LEMONGATE_CONFIG", ""),
		DevMode:      env("LEMONGATE_DEV", "") == "1",
		SessionHours: envInt("LEMONGATE_SESSION_HOURS", 12),
		OIDC: OIDCConfig{
			Issuer:       env("LEMONGATE_OIDC_ISSUER", ""),
			ClientID:     env("LEMONGATE_OIDC_CLIENT_ID", ""),
			ClientSecret: env("LEMONGATE_OIDC_CLIENT_SECRET", ""),
			Scopes:       envList("LEMONGATE_OIDC_SCOPES", []string{"openid", "email", "profile"}),
			RoleClaim:    env("LEMONGATE_OIDC_ROLE_CLAIM", "groups"),
			AdminValues:  envList("LEMONGATE_OIDC_ADMIN_VALUES", nil),
			DefaultRole:  env("LEMONGATE_OIDC_DEFAULT_ROLE", "member"),
			DefaultTeam:  env("LEMONGATE_OIDC_DEFAULT_TEAM", ""),
			ButtonLabel:  env("LEMONGATE_OIDC_BUTTON_LABEL", "Continue with SSO"),
		},
		SMTP: SMTPConfig{
			Host:     env("LEMONGATE_SMTP_HOST", ""),
			Port:     envInt("LEMONGATE_SMTP_PORT", 587),
			Username: env("LEMONGATE_SMTP_USERNAME", ""),
			Password: env("LEMONGATE_SMTP_PASSWORD", ""),
			From:     env("LEMONGATE_SMTP_FROM", ""),
			StartTLS: env("LEMONGATE_SMTP_STARTTLS", "1") == "1",
		},
	}
	if c.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}
	if c.MasterKey == "" {
		return nil, fmt.Errorf("LEMONGATE_MASTER_KEY is required")
	}
	if c.SecretKey == "" {
		c.SecretKey = c.MasterKey
	}
	if c.ConfigPath != "" {
		raw, err := os.ReadFile(c.ConfigPath)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		if err := yaml.Unmarshal([]byte(ExpandEnv(string(raw))), &c.File); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
		for i, m := range c.File.Models {
			if m.Name == "" || m.APIBase == "" {
				return nil, fmt.Errorf("config models[%d]: name and api_base are required", i)
			}
		}
	}
	return c, nil
}

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}`)

// ExpandEnv replaces ${VAR} and ${VAR:-default} references.
func ExpandEnv(s string) string {
	return envRef.ReplaceAllStringFunc(s, func(m string) string {
		parts := envRef.FindStringSubmatch(m)
		if v, ok := os.LookupEnv(parts[1]); ok {
			return v
		}
		return parts[2]
	})
}
