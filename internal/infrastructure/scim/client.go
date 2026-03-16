// Package scim implements a SCIM 2.0 provisioning client for pushing user
// lifecycle events (create, update, deactivate) to external service providers.
// Casdoor exposes a SCIM 2.0 endpoint natively; this client calls downstream
// SPs that consume SCIM from the hub.
package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/enterprise/sso-identity-hub/internal/config"
)

// SCIMUser represents the SCIM 2.0 User resource as defined in RFC 7643.
type SCIMUser struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id,omitempty"`
	ExternalID  string      `json:"externalId,omitempty"`
	UserName    string      `json:"userName"`
	DisplayName string      `json:"displayName,omitempty"`
	Active      bool        `json:"active"`
	Emails      []SCIMEmail `json:"emails,omitempty"`
	Photos      []SCIMPhoto `json:"photos,omitempty"`
	Meta        *SCIMMeta   `json:"meta,omitempty"`
}

type SCIMEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary"`
	Type    string `json:"type,omitempty"`
}

type SCIMPhoto struct {
	Value string `json:"value"`
	Type  string `json:"type,omitempty"`
}

type SCIMMeta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created,omitempty"`
	LastModified time.Time `json:"lastModified,omitempty"`
}

var scimUserSchemas = []string{"urn:ietf:params:scim:schemas:core:2.0:User"}

// Client is a SCIM 2.0 service provider client that pushes provisioning events.
type Client struct {
	cfg        config.SCIMConfig
	httpClient *http.Client
}

// NewClient constructs the SCIM client with a sensible default timeout.
func NewClient(cfg config.SCIMConfig) *Client {
	return &Client{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// ProvisionUser creates or updates a user at the downstream SCIM endpoint.
// It first attempts to find the user by externalId and updates if found.
func (c *Client) ProvisionUser(ctx context.Context, user SCIMUser) error {
	user.Schemas = scimUserSchemas

	existing, err := c.findByExternalID(ctx, user.ExternalID)
	if err == nil && existing != nil {
		return c.updateUser(ctx, existing.ID, user)
	}

	return c.createUser(ctx, user)
}

// DeprovisionUser sets a user's active flag to false at the downstream SP.
// Per SCIM spec, deletion is modelled as deactivation to preserve audit trails.
func (c *Client) DeprovisionUser(ctx context.Context, externalID string) error {
	existing, err := c.findByExternalID(ctx, externalID)
	if err != nil || existing == nil {
		return fmt.Errorf("scim deprovision: user with externalId %q not found", externalID)
	}

	patch := map[string]interface{}{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]interface{}{
			{"op": "replace", "path": "active", "value": false},
		},
	}
	return c.doPatch(ctx, existing.ID, patch)
}

func (c *Client) createUser(ctx context.Context, user SCIMUser) error {
	body, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("marshal scim user: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.ExternalEndpoint+"/Users", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build scim create request: %w", err)
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("scim create user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("scim create returned HTTP %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

func (c *Client) updateUser(ctx context.Context, scimID string, user SCIMUser) error {
	body, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("marshal scim user update: %w", err)
	}

	endpoint := fmt.Sprintf("%s/Users/%s", c.cfg.ExternalEndpoint, scimID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build scim put request: %w", err)
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("scim update user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("scim put returned HTTP %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

func (c *Client) doPatch(ctx context.Context, scimID string, patch interface{}) error {
	body, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("marshal scim patch: %w", err)
	}

	endpoint := fmt.Sprintf("%s/Users/%s", c.cfg.ExternalEndpoint, scimID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build scim patch request: %w", err)
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("scim patch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("scim patch returned HTTP %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

func (c *Client) findByExternalID(ctx context.Context, externalID string) (*SCIMUser, error) {
	filter := fmt.Sprintf(`externalId eq "%s"`, externalID)
	endpoint := fmt.Sprintf("%s/Users?filter=%s", c.cfg.ExternalEndpoint, filter)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build scim filter request: %w", err)
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("scim filter: %w", err)
	}
	defer resp.Body.Close()

	var listResp struct {
		Resources    []SCIMUser `json:"Resources"`
		TotalResults int        `json:"totalResults"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, fmt.Errorf("decode scim list: %w", err)
	}

	if listResp.TotalResults == 0 || len(listResp.Resources) == 0 {
		return nil, nil
	}

	return &listResp.Resources[0], nil
}

func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.cfg.BearerToken)
	req.Header.Set("Content-Type", "application/scim+json")
	req.Header.Set("Accept", "application/scim+json")
}
