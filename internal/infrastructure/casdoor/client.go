// Package casdoor wraps the official casdoor-go-sdk and provides a clean
// interface for OIDC auth-code exchange, token introspection, and user lookup.
package casdoor

import (
	"context"
	"fmt"
	"strings"

	casdoorsdk "github.com/casdoor/casdoor-go-sdk/casdoorsdk"
	"golang.org/x/oauth2"

	"github.com/enterprise/sso-identity-hub/internal/config"
)

// UserInfo holds the normalized identity claims resolved from a Casdoor token.
type UserInfo struct {
	CasdoorID    string
	Email        string
	DisplayName  string
	AvatarURL    string
	Organization string
	MFAEnabled   bool
	// SID is the OIDC Session ID embedded by Casdoor in its ID tokens.
	SID string
}

// Client wraps the Casdoor SDK to provide IdP operations needed by the application layer.
type Client struct {
	cfg config.CasdoorConfig
}

// NewClient initialises the Casdoor SDK and returns a ready Client.
// The SDK stores its configuration globally, which is an SDK constraint;
// this wrapper isolates that side-effect from the rest of the codebase.
func NewClient(cfg config.CasdoorConfig) (*Client, error) {
	// CASDOOR_CERTIFICATE is stored in .env with literal \n escapes; convert to real newlines.
	cert := strings.ReplaceAll(cfg.Certificate, `\n`, "\n")
	casdoorsdk.InitConfig(
		cfg.Endpoint,
		cfg.ClientID,
		cfg.ClientSecret,
		cert,
		cfg.OrganizationName,
		cfg.ApplicationName,
	)
	return &Client{cfg: cfg}, nil
}

// ExchangeCode exchanges an OAuth 2.0 authorization code for a token pair.
// The code_verifier is passed through for PKCE validation on the Casdoor side.
func (c *Client) ExchangeCode(ctx context.Context, code, codeVerifier string) (*oauth2.Token, error) {
	token, err := casdoorsdk.GetOAuthToken(code, codeVerifier)
	if err != nil {
		return nil, fmt.Errorf("casdoor exchange code: %w", err)
	}
	return token, nil
}

// ParseIDToken validates and parses the Casdoor-issued ID token, returning typed claims.
func (c *Client) ParseIDToken(idToken string) (*UserInfo, error) {
	claims, err := casdoorsdk.ParseJwtToken(idToken)
	if err != nil {
		return nil, fmt.Errorf("casdoor parse id token: %w", err)
	}

	info := &UserInfo{
		CasdoorID:    claims.Id,
		Email:        claims.Email,
		DisplayName:  claims.DisplayName,
		AvatarURL:    claims.Avatar,
		Organization: claims.Owner,
	}

	// The sid claim in Casdoor tokens is not yet a standard field; fall back to sub.
	if claims.AccessToken != "" {
		info.SID = claims.AccessToken
	} else {
		info.SID = claims.Id
	}

	return info, nil
}

// GetUser fetches the full Casdoor user record by their Casdoor user name.
// Used to refresh MFA status and profile data after provisioning.
func (c *Client) GetUser(ctx context.Context, casdoorUserName string) (*casdoorsdk.User, error) {
	user, err := casdoorsdk.GetUser(casdoorUserName)
	if err != nil {
		return nil, fmt.Errorf("casdoor get user %q: %w", casdoorUserName, err)
	}
	return user, nil
}

// GetUsers returns all users belonging to the configured organisation.
// Used by the SCIM provisioning service for full-sync reconciliation.
func (c *Client) GetUsers(ctx context.Context) ([]*casdoorsdk.User, error) {
	users, err := casdoorsdk.GetUsers()
	if err != nil {
		return nil, fmt.Errorf("casdoor get users: %w", err)
	}
	return users, nil
}

// UpdateUser pushes attribute changes back to Casdoor (e.g., MFA status updates).
func (c *Client) UpdateUser(ctx context.Context, user *casdoorsdk.User) error {
	_, err := casdoorsdk.UpdateUser(user)
	if err != nil {
		return fmt.Errorf("casdoor update user %q: %w", user.Name, err)
	}
	return nil
}
