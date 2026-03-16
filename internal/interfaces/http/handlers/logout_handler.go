package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/enterprise/sso-identity-hub/internal/application/logout"
	"github.com/enterprise/sso-identity-hub/internal/interfaces/http/middleware"
	apperrors "github.com/enterprise/sso-identity-hub/pkg/errors"
)

// LogoutHandler manages session termination and back-channel logout dispatch.
type LogoutHandler struct {
	logoutSvc *logout.Service
}

func NewLogoutHandler(logoutSvc *logout.Service) *LogoutHandler {
	return &LogoutHandler{logoutSvc: logoutSvc}
}

// Logout terminates the authenticated user's current session and dispatches
// back-channel logout tokens to all registered third-party endpoints.
//
// POST /auth/logout
func (h *LogoutHandler) Logout(c *gin.Context) {
	userID, _ := middleware.UserIDFromContext(c)
	sessionID, _ := middleware.SessionIDFromContext(c)

	input := logout.LogoutInput{
		UserID:    userID,
		SessionID: &sessionID,
	}

	// Optional: caller may supply their Azure object ID for hard MS Graph revocation.
	if azureOID := c.GetHeader("X-Azure-Object-ID"); azureOID != "" {
		input.AzureObjectID = azureOID
	}

	if err := h.logoutSvc.Logout(c.Request.Context(), input); err != nil {
		c.JSON(apperrors.HTTPCodeOf(err), gin.H{"error": apperrors.ClientMessage(err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "logged out"})
}

// LogoutAll terminates ALL sessions for the authenticated user — equivalent to
// an admin-initiated forced logout. Also triggers MS Graph revocation if eligible.
//
// POST /auth/logout/all
func (h *LogoutHandler) LogoutAll(c *gin.Context) {
	userID, _ := middleware.UserIDFromContext(c)

	input := logout.LogoutInput{
		UserID:    userID,
		SessionID: nil, // nil = revoke all sessions
	}

	if azureOID := c.GetHeader("X-Azure-Object-ID"); azureOID != "" {
		input.AzureObjectID = azureOID
	}

	if err := h.logoutSvc.Logout(c.Request.Context(), input); err != nil {
		c.JSON(apperrors.HTTPCodeOf(err), gin.H{"error": apperrors.ClientMessage(err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "all sessions terminated"})
}

// AdminForceLogout allows an admin to forcefully terminate all sessions for
// any user by their internal UUID. Used for account suspension workflows.
//
// POST /admin/users/:user_id/logout
func (h *LogoutHandler) AdminForceLogout(c *gin.Context) {
	rawUserID := c.Param("user_id")
	targetUserID, err := uuid.Parse(rawUserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id"})
		return
	}

	input := logout.LogoutInput{
		UserID:    targetUserID,
		SessionID: nil,
	}

	if azureOID := c.Query("azure_oid"); azureOID != "" {
		input.AzureObjectID = azureOID
	}

	if err := h.logoutSvc.Logout(c.Request.Context(), input); err != nil {
		c.JSON(apperrors.HTTPCodeOf(err), gin.H{"error": apperrors.ClientMessage(err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "user sessions terminated", "user_id": targetUserID})
}
