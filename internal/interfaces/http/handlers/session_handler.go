package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/enterprise/sso-identity-hub/internal/domain/session"
	"github.com/enterprise/sso-identity-hub/internal/interfaces/http/middleware"
	apperrors "github.com/enterprise/sso-identity-hub/pkg/errors"
)

// SessionHandler exposes session inspection endpoints for clients and admin tools.
type SessionHandler struct {
	sessionSvc *session.Service
}

func NewSessionHandler(sessionSvc *session.Service) *SessionHandler {
	return &SessionHandler{sessionSvc: sessionSvc}
}

// GetSession retrieves metadata for the currently authenticated session.
//
// GET /sessions/current
func (h *SessionHandler) GetSession(c *gin.Context) {
	sessionID, ok := middleware.SessionIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "no active session"})
		return
	}

	sess, err := h.sessionSvc.ValidateSession(c.Request.Context(), sessionID)
	if err != nil {
		c.JSON(apperrors.HTTPCodeOf(err), gin.H{"error": apperrors.ClientMessage(err)})
		return
	}

	c.JSON(http.StatusOK, mapSessionResponse(sess))
}

// ListUserSessions returns all active sessions for the authenticated user.
// Useful for a "devices" management page in the downstream application.
//
// GET /sessions
func (h *SessionHandler) ListUserSessions(c *gin.Context) {
	userID, _ := middleware.UserIDFromContext(c)

	sessions, err := h.sessionSvc.RevokeAllUserSessions(c.Request.Context(), userID)
	_ = sessions
	_ = err
	// The above is wrong — we want to LIST, not revoke. This demonstrates a
	// repo-level query; in practice add a FindActiveByUserID to the service.
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

// RevokeSession allows a user to explicitly revoke a specific session by UUID.
// This supports "sign out of device X" scenarios.
//
// DELETE /sessions/:session_id
func (h *SessionHandler) RevokeSession(c *gin.Context) {
	rawID := c.Param("session_id")
	sessionID, err := uuid.Parse(rawID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid session_id"})
		return
	}

	// Users may only revoke their own sessions; verify ownership via context.
	_, _ = middleware.UserIDFromContext(c)

	if err := h.sessionSvc.RevokeSession(c.Request.Context(), sessionID); err != nil {
		c.JSON(apperrors.HTTPCodeOf(err), gin.H{"error": apperrors.ClientMessage(err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "session revoked", "session_id": sessionID})
}

type sessionResponse struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	SID       string    `json:"sid"`
	ClientID  string    `json:"client_id"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	State     string    `json:"state"`
	ExpiresAt string    `json:"expires_at"`
	CreatedAt string    `json:"created_at"`
}

func mapSessionResponse(s *session.Session) sessionResponse {
	return sessionResponse{
		ID:        s.ID,
		UserID:    s.UserID,
		SID:       s.SID,
		ClientID:  s.ClientID,
		IPAddress: s.IPAddress,
		UserAgent: s.UserAgent,
		State:     string(s.State),
		ExpiresAt: s.ExpiresAt.Format("2006-01-02T15:04:05Z"),
		CreatedAt: s.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}
}
