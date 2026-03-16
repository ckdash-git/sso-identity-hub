// Package config loads and validates all application configuration using Viper.
// Configuration sources (in priority order): env vars > .env file > defaults.
package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config is the root configuration object injected across the entire application.
type Config struct {
	Server      ServerConfig
	Postgres    PostgresConfig
	Casdoor     CasdoorConfig
	OIDC        OIDCConfig
	JWT         JWTConfig
	TokenPolicy TokenPolicyConfig
	BackChannel BackChannelConfig
	MSGraph     MSGraphConfig
	SCIM        SCIMConfig
	RateLimit   RateLimitConfig
	Log         LogConfig
}

type ServerConfig struct {
	Port         int
	Env          string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

type PostgresConfig struct {
	Host            string
	Port            int
	User            string
	Password        string
	Database        string
	SSLMode         string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

// DSN returns a standard PostgreSQL connection string.
func (p PostgresConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		p.Host, p.Port, p.User, p.Password, p.Database, p.SSLMode,
	)
}

// URL returns a PostgreSQL connection URL with the postgres:// scheme.
// Required by golang-migrate which expects a URL, not a key=value DSN.
func (p PostgresConfig) URL() string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s",
		url.QueryEscape(p.User), url.QueryEscape(p.Password),
		p.Host, p.Port, p.Database, p.SSLMode,
	)
}

type CasdoorConfig struct {
	Endpoint         string
	ClientID         string
	ClientSecret     string
	OrganizationName string
	ApplicationName  string
	Certificate      string
}

type OIDCConfig struct {
	IssuerURL   string
	RedirectURI string
	Scopes      []string
}

type JWTConfig struct {
	// Path to PEM-encoded RSA-2048 private key for RS256 signing of logout tokens.
	PrivateKeyPath string
	PublicKeyPath  string
	KeyID          string
}

// TokenPolicyConfig enforces sign-in frequency. Both values should be equal to
// synchronize the access token and refresh token expiry windows (4-8 hours).
type TokenPolicyConfig struct {
	MaxAgeDuration        time.Duration
	RefreshMaxAgeDuration time.Duration
}

type BackChannelConfig struct {
	Endpoints  []string
	Timeout    time.Duration
	MaxRetries int
}

type MSGraphConfig struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	Scope        string
}

type SCIMConfig struct {
	BearerToken      string
	ExternalEndpoint string
}

type RateLimitConfig struct {
	RequestsPerMinute int64
}

type LogConfig struct {
	Level  string
	Format string
}

// Load reads configuration from environment variables and an optional .env file.
// It returns a fully populated and validated Config or an error.
func Load() (*Config, error) {
	v := viper.New()

	v.SetConfigFile(".env")
	v.SetConfigType("env")
	// AutomaticEnv ensures that environment variables always take precedence over the file.
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Ignore missing .env file; in production, all values come from the environment.
	_ = v.ReadInConfig()

	setDefaults(v)

	cfg := &Config{}
	if err := bind(v, cfg); err != nil {
		return nil, fmt.Errorf("config bind: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	return cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("SERVER_PORT", 8080)
	v.SetDefault("SERVER_ENV", "development")
	v.SetDefault("SERVER_READ_TIMEOUT_SECONDS", 30)
	v.SetDefault("SERVER_WRITE_TIMEOUT_SECONDS", 30)
	v.SetDefault("SERVER_IDLE_TIMEOUT_SECONDS", 120)
	v.SetDefault("POSTGRES_PORT", 5432)
	v.SetDefault("POSTGRES_SSLMODE", "require")
	v.SetDefault("POSTGRES_MAX_OPEN_CONNS", 25)
	v.SetDefault("POSTGRES_MAX_IDLE_CONNS", 10)
	v.SetDefault("POSTGRES_CONN_MAX_LIFETIME_MINUTES", 5)
	v.SetDefault("TOKEN_MAX_AGE_SECONDS", 28800)
	v.SetDefault("TOKEN_REFRESH_MAX_AGE_SECONDS", 28800)
	v.SetDefault("BACKCHANNEL_LOGOUT_TIMEOUT_SECONDS", 5)
	v.SetDefault("BACKCHANNEL_LOGOUT_MAX_RETRIES", 3)
	v.SetDefault("RATE_LIMIT_REQUESTS_PER_MINUTE", 60)
	v.SetDefault("LOG_LEVEL", "info")
	v.SetDefault("LOG_FORMAT", "json")
}

func bind(v *viper.Viper, cfg *Config) error {
	cfg.Server = ServerConfig{
		Port:         v.GetInt("SERVER_PORT"),
		Env:          v.GetString("SERVER_ENV"),
		ReadTimeout:  time.Duration(v.GetInt("SERVER_READ_TIMEOUT_SECONDS")) * time.Second,
		WriteTimeout: time.Duration(v.GetInt("SERVER_WRITE_TIMEOUT_SECONDS")) * time.Second,
		IdleTimeout:  time.Duration(v.GetInt("SERVER_IDLE_TIMEOUT_SECONDS")) * time.Second,
	}

	cfg.Postgres = PostgresConfig{
		Host:            v.GetString("POSTGRES_HOST"),
		Port:            v.GetInt("POSTGRES_PORT"),
		User:            v.GetString("POSTGRES_USER"),
		Password:        v.GetString("POSTGRES_PASSWORD"),
		Database:        v.GetString("POSTGRES_DB"),
		SSLMode:         v.GetString("POSTGRES_SSLMODE"),
		MaxOpenConns:    v.GetInt("POSTGRES_MAX_OPEN_CONNS"),
		MaxIdleConns:    v.GetInt("POSTGRES_MAX_IDLE_CONNS"),
		ConnMaxLifetime: time.Duration(v.GetInt("POSTGRES_CONN_MAX_LIFETIME_MINUTES")) * time.Minute,
	}

	cfg.Casdoor = CasdoorConfig{
		Endpoint:         v.GetString("CASDOOR_ENDPOINT"),
		ClientID:         v.GetString("CASDOOR_CLIENT_ID"),
		ClientSecret:     v.GetString("CASDOOR_CLIENT_SECRET"),
		OrganizationName: v.GetString("CASDOOR_ORGANIZATION_NAME"),
		ApplicationName:  v.GetString("CASDOOR_APPLICATION_NAME"),
		Certificate:      v.GetString("CASDOOR_CERTIFICATE"),
	}

	cfg.OIDC = OIDCConfig{
		IssuerURL:   v.GetString("OIDC_ISSUER_URL"),
		RedirectURI: v.GetString("OIDC_REDIRECT_URI"),
		Scopes:      strings.Split(v.GetString("OIDC_SCOPES"), ","),
	}

	cfg.JWT = JWTConfig{
		PrivateKeyPath: v.GetString("JWT_RS256_PRIVATE_KEY_PATH"),
		PublicKeyPath:  v.GetString("JWT_RS256_PUBLIC_KEY_PATH"),
		KeyID:          v.GetString("JWT_KEY_ID"),
	}

	cfg.TokenPolicy = TokenPolicyConfig{
		MaxAgeDuration:        time.Duration(v.GetInt64("TOKEN_MAX_AGE_SECONDS")) * time.Second,
		RefreshMaxAgeDuration: time.Duration(v.GetInt64("TOKEN_REFRESH_MAX_AGE_SECONDS")) * time.Second,
	}

	rawEndpoints := v.GetString("BACKCHANNEL_LOGOUT_ENDPOINTS")
	var endpoints []string
	for _, ep := range strings.Split(rawEndpoints, ",") {
		ep = strings.TrimSpace(ep)
		if ep != "" {
			endpoints = append(endpoints, ep)
		}
	}
	cfg.BackChannel = BackChannelConfig{
		Endpoints:  endpoints,
		Timeout:    time.Duration(v.GetInt("BACKCHANNEL_LOGOUT_TIMEOUT_SECONDS")) * time.Second,
		MaxRetries: v.GetInt("BACKCHANNEL_LOGOUT_MAX_RETRIES"),
	}

	cfg.MSGraph = MSGraphConfig{
		TenantID:     v.GetString("MSGRAPH_TENANT_ID"),
		ClientID:     v.GetString("MSGRAPH_CLIENT_ID"),
		ClientSecret: v.GetString("MSGRAPH_CLIENT_SECRET"),
		Scope:        v.GetString("MSGRAPH_SCOPE"),
	}

	cfg.SCIM = SCIMConfig{
		BearerToken:      v.GetString("SCIM_BEARER_TOKEN"),
		ExternalEndpoint: v.GetString("SCIM_EXTERNAL_ENDPOINT"),
	}

	cfg.RateLimit = RateLimitConfig{
		RequestsPerMinute: v.GetInt64("RATE_LIMIT_REQUESTS_PER_MINUTE"),
	}

	cfg.Log = LogConfig{
		Level:  v.GetString("LOG_LEVEL"),
		Format: v.GetString("LOG_FORMAT"),
	}

	return nil
}

// validate returns an error if any required configuration fields are absent.
func (c *Config) validate() error {
	required := map[string]string{
		"POSTGRES_HOST":              c.Postgres.Host,
		"POSTGRES_USER":              c.Postgres.User,
		"POSTGRES_PASSWORD":          c.Postgres.Password,
		"POSTGRES_DB":                c.Postgres.Database,
		"CASDOOR_ENDPOINT":           c.Casdoor.Endpoint,
		"CASDOOR_CLIENT_ID":          c.Casdoor.ClientID,
		"CASDOOR_CLIENT_SECRET":      c.Casdoor.ClientSecret,
		"OIDC_ISSUER_URL":            c.OIDC.IssuerURL,
		"JWT_RS256_PRIVATE_KEY_PATH": c.JWT.PrivateKeyPath,
		"JWT_RS256_PUBLIC_KEY_PATH":  c.JWT.PublicKeyPath,
	}

	var missing []string
	for key, val := range required {
		if strings.TrimSpace(val) == "" {
			missing = append(missing, key)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required env vars: %s", strings.Join(missing, ", "))
	}

	if c.TokenPolicy.MaxAgeDuration < 1*time.Hour || c.TokenPolicy.MaxAgeDuration > 24*time.Hour {
		return fmt.Errorf("TOKEN_MAX_AGE_SECONDS must be between 3600 and 86400 (1–24 hours)")
	}

	return nil
}
