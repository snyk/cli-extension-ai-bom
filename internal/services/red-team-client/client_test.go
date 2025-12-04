package redteamclient_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/snyk/cli-extension-ai-bom/mocks/frameworkmock"
	"github.com/snyk/cli-extension-ai-bom/mocks/loggermock"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking"

	redteam_errors "github.com/snyk/cli-extension-ai-bom/internal/errors/redteam"
	redteamclient "github.com/snyk/cli-extension-ai-bom/internal/services/red-team-client"
)

func isCreateAIScanReq(r *http.Request) bool {
	return r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/ai_scans")
}

const (
	userAgent = "test-user-agent"
	orgID     = "test-org-id"
)

var defaultConfig = redteamclient.RedTeamConfig{
	Target: redteamclient.AIScanTarget{
		Name: "test-target",
		Type: "test-type",
		Settings: redteamclient.AIScanSettings{
			URL: "test-url",
		},
	},
}

func writeCreateScanResponse(w http.ResponseWriter, scanID string) {
	response := redteamclient.CreateAIScanResponse{
		Data: redteamclient.AIScan{
			ID: scanID,
		},
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

func setupTestClient(t *testing.T, serverURL string) *redteamclient.ClientImpl {
	t.Helper()
	logger := loggermock.NewNoOpLogger()
	ictx := frameworkmock.NewMockInvocationContext(t)

	// Configure the Snyk HTTP client to match production behavior for error handling.
	// The Snyk networking library uses a ResponseMiddleware that intercepts HTTP responses
	// and converts error status codes (400+) to snyk_errors.Error objects. This middleware
	// is only added to the transport chain if:
	// 1. An error handler is registered via AddErrorHandler()
	// 2. The request URL matches a known host (API_URL or AUTHENTICATION_ADDITIONAL_URLS)

	// See https://github.com/snyk/go-application-framework/blob/main/pkg/networking/middleware/response.go#L63 for more details.

	// TODO(pkey): move this to the shared frameworkmock setup.
	mockConfig := ictx.GetConfiguration()
	mockConfig.Set(configuration.API_URL, "https://api.snyk.io")
	mockConfig.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, []string{"http://127.0.0.1", "http://localhost"})

	networkAccess := networking.NewNetworkAccess(mockConfig)
	networkAccess.AddErrorHandler(func(err error, _ context.Context) error {
		return err
	})

	return redteamclient.NewRedTeamClient(
		logger,
		networkAccess.GetHttpClient(),
		userAgent,
		serverURL,
	)
}

func TestRedTeamClient_CreateScan_Happy(t *testing.T) {
	var scanID string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isCreateAIScanReq(r) {
			scanID = uuid.New().String()
			writeCreateScanResponse(w, scanID)
		} else {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := setupTestClient(t, server.URL)

	result, err := client.CreateScan(context.Background(), orgID, &defaultConfig)
	assert.Nil(t, err)
	assert.NotEmpty(t, result)
	assert.Equal(t, scanID, result)
}

func TestRedTeamClient_CreateScan_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	}))
	defer server.Close()

	client := setupTestClient(t, server.URL)

	result, err := client.CreateScan(context.Background(), orgID, &defaultConfig)
	assert.NotNil(t, err)
	assert.Empty(t, result)
}

func TestRedTeamClient_GetScanResults_Happy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/hidden/orgs/test-org-id/ai_scans/test-scan-id/vulnerabilities", r.URL.Path)

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(redteamclient.GetAIVulnerabilitiesResponse{
			Data: redteamclient.GetAIVulnerabilitiesResponseData{
				ID: "test-scan-id",
				Results: []redteamclient.AIVulnerability{
					{
						ID: "test_vulnerability_id",
						Definition: redteamclient.AIVulnerabilityDefinition{
							ID:          "test_vulnerability_definition_id",
							Name:        "test_vulnerability_name",
							Description: "test_vulnerability_description",
						},
						Severity: "high",
					},
				},
			},
		})
	}))
	defer server.Close()

	client := setupTestClient(t, server.URL)

	results, err := client.GetScanResults(context.Background(), orgID, "test-scan-id")
	assert.Nil(t, err)
	assert.NotEmpty(t, results)
	assert.Equal(t, "test-scan-id", results.ID)
}

func TestRedTeamClient_CreateScan_BadRequestError(t *testing.T) {
	errorDetail := "Maximum number of concurrent scans reached."
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusBadRequest)
		errorResponse := map[string]interface{}{
			"errors": []map[string]interface{}{
				{
					"title":  "Bad Request",
					"detail": errorDetail,
					"status": "400",
				},
			},
		}
		json.NewEncoder(w).Encode(errorResponse)
	}))
	defer server.Close()

	client := setupTestClient(t, server.URL)

	result, err := client.CreateScan(context.Background(), orgID, &defaultConfig)
	assert.Empty(t, result)
	require.NotNil(t, err)

	var redTeamErr *redteam_errors.RedTeamError
	require.True(t, errors.As(err, &redTeamErr), "error should be a RedTeamError")
	assert.Contains(t, err.Error(), errorDetail, "error detail should be passed through")
}
