// Package msgraph provides a client for the Microsoft Graph API.
// Its primary purpose in this system is immediate refresh-token revocation
// for Azure AD / Entra ID users, enabling hard lockouts that bypass the
// normal token TTL window defined by the sign-in frequency policy.
package msgraph

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/enterprise/sso-identity-hub/internal/config"
)

const (
	graphBaseURL     = "https://graph.microsoft.com/v1.0"
	tokenEndpointFmt = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
)

// Client authenticates with Azure AD using client credentials and calls the
// Graph API to revoke user refresh tokens.
type Client struct {
	cfg        config.MSGraphConfig
	httpClient *http.Client
	// cachedToken and tokenExpiry support simple in-memory token caching to
	// avoid fetching a new client-credentials token on every revocation call.
	cachedToken string
	tokenExpiry time.Time
}

// NewClient constructs a Graph API client. The HTTP client timeout is set to
// 15s to prevent revocation calls from blocking the logout request pipeline.
func NewClient(cfg config.MSGraphConfig) *Client {
	return &Client{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// RevokeUserRefreshTokens calls the Graph API revokeSignInSessions action for
// the given Azure AD object ID. This immediately invalidates all refresh tokens
// for the user across all applications in the tenant.
// See: https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions
func (c *Client) RevokeUserRefreshTokens(ctx context.Context, azureObjectID string) error {
	accessToken, err := c.getAccessToken(ctx)
	if err != nil {
		return fmt.Errorf("get graph access token: %w", err)
	}

	endpoint := fmt.Sprintf("%s/users/%s/revokeSignInSessions", graphBaseURL, azureObjectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return fmt.Errorf("build revoke request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("execute revoke request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("graph revoke returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// getAccessToken returns a valid client-credentials access token, refreshing
// it if the cached copy is within 60 seconds of expiry.
func (c *Client) getAccessToken(ctx context.Context) (string, error) {
	if c.cachedToken != "" && time.Now().Add(60*time.Second).Before(c.tokenExpiry) {
		return c.cachedToken, nil
	}

	tokenURL := fmt.Sprintf(tokenEndpointFmt, c.cfg.TenantID)
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.cfg.ClientID},
		"client_secret": {c.cfg.ClientSecret},
		"scope":         {c.cfg.Scope},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token endpoint returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}

	c.cachedToken = result.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)

	return c.cachedToken, nil
}
