package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/enterprise/sso-identity-hub/internal/application/provisioning"
	apperrors "github.com/enterprise/sso-identity-hub/pkg/errors"
)

// SCIMHandler exposes SCIM provisioning triggers for admin workflows.
// These endpoints are protected by the RequireSession middleware.
type SCIMHandler struct {
	provisioningSvc *provisioning.Service
}

func NewSCIMHandler(provisioningSvc *provisioning.Service) *SCIMHandler {
	return &SCIMHandler{provisioningSvc: provisioningSvc}
}

// ProvisionUser triggers an immediate SCIM push for the given user.
// Called after profile changes in Casdoor that need to sync to downstream SPs.
//
// POST /admin/users/:user_id/provision
func (h *SCIMHandler) ProvisionUser(c *gin.Context) {
	userID, err := parseUserID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id"})
		return
	}

	if err := h.provisioningSvc.ProvisionToSCIM(c.Request.Context(), userID); err != nil {
		c.JSON(apperrors.HTTPCodeOf(err), gin.H{"error": apperrors.ClientMessage(err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "user provisioned", "user_id": userID})
}

// DeprovisionUser deactivates the user at the downstream SCIM endpoint.
//
// POST /admin/users/:user_id/deprovision
func (h *SCIMHandler) DeprovisionUser(c *gin.Context) {
	userID, err := parseUserID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id"})
		return
	}

	if err := h.provisioningSvc.DeprovisionFromSCIM(c.Request.Context(), userID); err != nil {
		c.JSON(apperrors.HTTPCodeOf(err), gin.H{"error": apperrors.ClientMessage(err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "user deprovisioned", "user_id": userID})
}

func parseUserID(c *gin.Context) (uuid.UUID, error) {
	return uuid.Parse(c.Param("user_id"))
}
