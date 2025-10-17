package redteamclient_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/snyk/cli-extension-ai-bom/mocks/frameworkmock"
	"github.com/snyk/cli-extension-ai-bom/mocks/loggermock"

	"github.com/stretchr/testify/assert"

	redteamclient "github.com/snyk/cli-extension-ai-bom/internal/services/red-team-client"
)

func isCreateAIScanReq(r *http.Request) bool {
	return r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/ai_scans")
}

func isGetAIScanReq(r *http.Request) bool {
	return r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/ai_scans/")
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

func TestRedTeamClient_RunScan_Happy(t *testing.T) {
	pollCount := 0
	var scanID string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case isCreateAIScanReq(r):
			scanID = uuid.New().String()
			response := redteamclient.CreateAIScanResponse{
				Data: redteamclient.AIScan{
					ID: scanID,
				},
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(response)

		case isGetAIScanReq(r):
			pollCount++
			if pollCount < 3 {
				response := redteamclient.GetAIScanResponse{
					Data: redteamclient.AIScan{
						Status: redteamclient.AIScanStatusStarted,
					},
				}
				json.NewEncoder(w).Encode(response)
			} else {
				response := redteamclient.GetAIScanResponse{
					Data: redteamclient.AIScan{
						Status: redteamclient.AIScanStatusCompleted,
					},
				}
				json.NewEncoder(w).Encode(response)
			}

		default:
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		}
	}))
	defer server.Close()

	logger := loggermock.NewNoOpLogger()
	ictx := frameworkmock.NewMockInvocationContext(t)

	client := redteamclient.NewRedTeamClient(
		logger,
		ictx.GetNetworkAccess().GetHttpClient(),
		ictx.GetUserInterface(),
		userAgent,
		server.URL,
	)

	result, err := client.RunScan(context.Background(), orgID, &defaultConfig)
	assert.Nil(t, err)
	assert.NotEmpty(t, result)
	assert.Equal(t, scanID, result)
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

	logger := loggermock.NewNoOpLogger()
	ictx := frameworkmock.NewMockInvocationContext(t)
	client := redteamclient.NewRedTeamClient(
		logger,
		ictx.GetNetworkAccess().GetHttpClient(),
		ictx.GetUserInterface(),
		userAgent,
		server.URL,
	)

	results, err := client.GetScanResults(context.Background(), orgID, "test-scan-id")
	assert.Nil(t, err)
	assert.NotEmpty(t, results)
	assert.Equal(t, "test-scan-id", results.ID)
}
