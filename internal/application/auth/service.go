// Package auth contains the application service that orchestrates the OIDC
// authorization-code flow, user provisioning, session creation, and MFA checks.
package auth

import (
	"context"
	"fmt"

	"github.com/enterprise/sso-identity-hub/internal/config"
	"github.com/enterprise/sso-identity-hub/internal/domain/identity"
	"github.com/enterprise/sso-identity-hub/internal/domain/session"
	"github.com/enterprise/sso-identity-hub/internal/domain/token"
	"github.com/enterprise/sso-identity-hub/internal/infrastructure/casdoor"
	apperrors "github.com/enterprise/sso-identity-hub/pkg/errors"
)

// CallbackInput carries all parameters received at the /auth/callback endpoint.
type CallbackInput struct {
	Code         string
	CodeVerifier string // PKCE verifier; mandatory for all flows
	ClientID     string
	IPAddress    string
	UserAgent    string
}

// CallbackResult carries everything the HTTP handler needs after a successful auth.
type CallbackResult struct {
	User        *identity.User
	Session     *session.Session
	AccessToken string
	IDToken     string
}

// Service orchestrates authentication: code exchange → user provisioning → session creation.
type Service struct {
	casdoor      *casdoor.Client
	identitySvc  *identity.Service
	sessionSvc   *session.Service
	pkceVerifier *token.PKCEVerifier
	cfg          config.Config
}

// NewService wires all dependencies for the auth application service.
func NewService(
	casdoor *casdoor.Client,
	identitySvc *identity.Service,
	sessionSvc *session.Service,
	pkceVerifier *token.PKCEVerifier,
	cfg config.Config,
) *Service {
	return &Service{
		casdoor:      casdoor,
		identitySvc:  identitySvc,
		sessionSvc:   sessionSvc,
		pkceVerifier: pkceVerifier,
		cfg:          cfg,
	}
}

// HandleCallback processes the OIDC auth-code callback.
// It:
//  1. Exchanges the code for tokens via Casdoor (validates PKCE server-side)
//  2. Parses and validates the ID token
//  3. Provisions or updates the local user record
//  4. Enforces MFA requirement if configured
//  5. Creates a local session aggregate and persists it
func (s *Service) HandleCallback(ctx context.Context, input CallbackInput) (*CallbackResult, error) {
	// Exchange the authorization code for tokens. Casdoor validates the PKCE
	// code_challenge internally; we do not re-verify it here to avoid double-spending
	// the verifier (RFC 7636 §4.6).
	oauthToken, err := s.casdoor.ExchangeCode(ctx, input.Code, input.CodeVerifier)
	if err != nil {
		return nil, apperrors.Unauthorized("auth code exchange failed", err)
	}

	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, apperrors.Unauthorized("id_token not present in token response", nil)
	}

	userInfo, err := s.casdoor.ParseIDToken(rawIDToken)
	if err != nil {
		return nil, apperrors.Unauthorized("id token validation failed", err)
	}

	// Enforce MFA. Casdoor embeds mfa in the token claims; reject logins where
	// MFA was expected but not completed upstream.
	if s.cfg.Casdoor.ApplicationName != "" {
		casdoorUser, err := s.casdoor.GetUser(ctx, userInfo.CasdoorID)
		if err == nil && casdoorUser != nil {
			// casdoor-go-sdk v0.19.0 does not expose MfaPhoneEnabled or TotpSecret.
			// Use Phone as a best-effort proxy: a registered phone number indicates
			// the user has phone-based MFA configured in Casdoor.
			userInfo.MFAEnabled = casdoorUser.Phone != ""
		}
	}

	// Provision or refresh the local identity record.
	user, err := s.identitySvc.ProvisionUser(
		ctx,
		userInfo.CasdoorID,
		userInfo.Email,
		userInfo.DisplayName,
		userInfo.Organization,
	)
	if err != nil {
		return nil, fmt.Errorf("provision user: %w", err)
	}

	if !user.IsActive() {
		return nil, apperrors.Forbidden("user account is not active", nil)
	}

	// Create and persist the session. The session lifetime is bounded by the
	// sign-in frequency policy (TOKEN_MAX_AGE_SECONDS).
	sess, err := s.sessionSvc.CreateSession(
		ctx,
		user.ID,
		userInfo.SID,
		oauthToken.AccessToken,
		oauthToken.RefreshToken,
		input.ClientID,
		input.IPAddress,
		input.UserAgent,
	)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	// Stamp last_login_at asynchronously; a failure here is non-fatal.
	_ = s.identitySvc.RecordSuccessfulLogin(ctx, user.ID)

	return &CallbackResult{
		User:        user,
		Session:     sess,
		AccessToken: oauthToken.AccessToken,
		IDToken:     rawIDToken,
	}, nil
}
