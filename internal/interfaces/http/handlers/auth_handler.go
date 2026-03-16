// Package handlers contains Gin HTTP handlers for all SSO hub endpoints.
package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/enterprise/sso-identity-hub/internal/application/auth"
	"github.com/enterprise/sso-identity-hub/internal/interfaces/http/middleware"
	apperrors "github.com/enterprise/sso-identity-hub/pkg/errors"
)

// AuthHandler handles OIDC authorization flow endpoints.
type AuthHandler struct {
	authSvc *auth.Service
}

// NewAuthHandler constructs the auth handler.
func NewAuthHandler(authSvc *auth.Service) *AuthHandler {
	return &AuthHandler{authSvc: authSvc}
}

// HandleCallback processes the OIDC authorization-code callback.
// It expects code, state, and code_verifier (PKCE) as query parameters.
//
// GET/POST /auth/callback
func (h *AuthHandler) HandleCallback(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing authorization code"})
		return
	}

	codeVerifier := c.Query("code_verifier")
	if codeVerifier == "" {
		// PKCE is mandatory for all flows in this implementation.
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code_verifier (PKCE required)"})
		return
	}

	clientID := c.Query("client_id")

	result, err := h.authSvc.HandleCallback(c.Request.Context(), auth.CallbackInput{
		Code:         code,
		CodeVerifier: codeVerifier,
		ClientID:     clientID,
		IPAddress:    c.ClientIP(),
		UserAgent:    c.Request.UserAgent(),
	})
	if err != nil {
		c.JSON(apperrors.HTTPCodeOf(err), gin.H{"error": apperrors.ClientMessage(err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"session_id":   result.Session.ID,
		"user_id":      result.User.ID,
		"email":        result.User.Email,
		"display_name": result.User.DisplayName,
		"access_token": result.AccessToken,
		"expires_at":   result.Session.ExpiresAt,
	})
}

// HealthCheck returns service liveness status.
//
// GET /healthz
func HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// JWKSHandler serves the RS256 public key as a JWKS document.
// Third parties use this to verify logout token signatures without
// needing to share a symmetric secret.
//
// GET /.well-known/jwks.json
type JWKSHandler struct {
	jwks gin.H // pre-computed at startup to avoid per-request key serialisation
}

func NewJWKSHandler(jwks gin.H) *JWKSHandler {
	return &JWKSHandler{jwks: jwks}
}

func (h *JWKSHandler) ServeJWKS(c *gin.Context) {
	c.JSON(http.StatusOK, h.jwks)
}

// WhoAmI returns the authenticated user's identity from the current session.
//
// GET /auth/me
func WhoAmI(c *gin.Context) {
	userID, ok := middleware.UserIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}
	sessionID, _ := middleware.SessionIDFromContext(c)

	c.JSON(http.StatusOK, gin.H{
		"user_id":    userID,
		"session_id": sessionID,
	})
}
