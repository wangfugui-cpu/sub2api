package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestGatewayHandlerKeyIdentityReturnsOnlySafeIdentityFields(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/sub2api/identity", nil)
	c.Set(string(middleware2.ContextKeyAPIKey), &service.APIKey{
		ID: 77,
		Key: "sk-sensitive-value",
		Name: "Family tablet",
		User: &service.User{
			ID:       42,
			Username: "Family Member",
			Email:    "private@example.com",
			Balance:  99.5,
		},
	})

	(&GatewayHandler{}).KeyIdentity(c)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	var got keyIdentityResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	require.Equal(t, "sub2api.key_identity", got.Object)
	require.Equal(t, 2, got.SchemaVersion)
	require.Equal(t, "sub2api:user:42", got.Subject)
	require.Equal(t, int64(42), got.User.ID)
	require.Equal(t, "Family Member", got.User.Name)
	require.Equal(t, int64(77), got.Key.ID)
	require.Equal(t, "Family tablet", got.Key.Name)
	require.NotContains(t, w.Body.String(), "sk-sensitive-value")
	require.NotContains(t, w.Body.String(), "private@example.com")
	require.NotContains(t, w.Body.String(), "99.5")
}

func TestGatewayHandlerKeyIdentityRejectsMissingKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/sub2api/identity", nil)

	(&GatewayHandler{}).KeyIdentity(c)

	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestKeyIdentityDisplayNameFallsBackToStableLabel(t *testing.T) {
	require.Equal(t, "Sub2API User 7", keyIdentityDisplayName(&service.User{ID: 7, Username: "  "}))
}

func TestKeyIdentityKeyDisplayNameDoesNotUseTheSecret(t *testing.T) {
	key := &service.APIKey{ID: 9, Key: "sk-sensitive-value", Name: "  "}
	require.Equal(t, "API Key 9", keyIdentityKeyDisplayName(key))
}
