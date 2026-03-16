package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/enterprise/sso-identity-hub/internal/domain/session"
	apperrors "github.com/enterprise/sso-identity-hub/pkg/errors"
)

const (
	contextKeySessionID = "session_id"
	contextKeyUserID    = "user_id"
)

// RequireSession is a middleware that validates an active session from the
// X-Session-ID request header. It is used to protect management endpoints.
// Public-facing OIDC endpoints (callback, JWKS) do not use this middleware.
func RequireSession(sessionSvc *session.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		rawID := c.GetHeader("X-Session-ID")
		if rawID == "" {
			// Also check Bearer token for API clients.
			authHeader := c.GetHeader("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				rawID = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if rawID == "" {
			abortWithError(c, apperrors.Unauthorized("missing session credential", nil))
			return
		}

		sessionID, err := uuid.Parse(rawID)
		if err != nil {
			abortWithError(c, apperrors.Unauthorized("malformed session id", err))
			return
		}

		sess, err := sessionSvc.ValidateSession(c.Request.Context(), sessionID)
		if err != nil {
			abortWithError(c, err)
			return
		}

		c.Set(contextKeySessionID, sess.ID)
		c.Set(contextKeyUserID, sess.UserID)
		c.Next()
	}
}

// SessionIDFromContext extracts the validated session UUID from a Gin context.
func SessionIDFromContext(c *gin.Context) (uuid.UUID, bool) {
	v, ok := c.Get(contextKeySessionID)
	if !ok {
		return uuid.Nil, false
	}
	id, ok := v.(uuid.UUID)
	return id, ok
}

// UserIDFromContext extracts the validated user UUID from a Gin context.
func UserIDFromContext(c *gin.Context) (uuid.UUID, bool) {
	v, ok := c.Get(contextKeyUserID)
	if !ok {
		return uuid.Nil, false
	}
	id, ok := v.(uuid.UUID)
	return id, ok
}

// abortWithError writes a typed error response and stops the handler chain.
func abortWithError(c *gin.Context, err error) {
	c.AbortWithStatusJSON(apperrors.HTTPCodeOf(err), gin.H{
		"error": apperrors.ClientMessage(err),
	})
}
