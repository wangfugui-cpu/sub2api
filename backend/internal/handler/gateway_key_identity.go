package handler

import (
	"net/http"
	"strconv"
	"strings"

	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

const keyIdentitySchemaVersion = 1

// keyIdentityResponse is deliberately small: a relying service only needs a
// stable subject and a display name. Email, balances, group details and the
// credential itself must never leave the gateway through this endpoint.
type keyIdentityResponse struct {
	Object        string                  `json:"object"`
	SchemaVersion int                     `json:"schema_version"`
	Subject       string                  `json:"subject"`
	User          keyIdentityUserResponse `json:"user"`
}

type keyIdentityUserResponse struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// KeyIdentity returns a privacy-preserving identity for the authenticated API
// key. It is intended for a trusted first-party application such as the
// personal Open WebUI deployment.
// GET /v1/sub2api/identity
func (h *GatewayHandler) KeyIdentity(c *gin.Context) {
	apiKey, ok := middleware2.GetAPIKeyFromContext(c)
	if !ok || apiKey.User == nil {
		h.errorResponse(c, http.StatusUnauthorized, "authentication_error", "Invalid API key")
		return
	}

	user := apiKey.User
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, keyIdentityResponse{
		Object:        "sub2api.key_identity",
		SchemaVersion: keyIdentitySchemaVersion,
		Subject:       keyIdentitySubject(user.ID),
		User: keyIdentityUserResponse{
			ID:   user.ID,
			Name: keyIdentityDisplayName(user),
		},
	})
}

func keyIdentitySubject(userID int64) string {
	return "sub2api:user:" + strconv.FormatInt(userID, 10)
}

func keyIdentityDisplayName(user *service.User) string {
	if name := strings.TrimSpace(user.Username); name != "" {
		return name
	}
	return "Sub2API User " + strconv.FormatInt(user.ID, 10)
}
