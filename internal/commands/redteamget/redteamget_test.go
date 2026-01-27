package redteamget_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-ai-bom/internal/commands/redteamget"
	redteam_errors "github.com/snyk/cli-extension-ai-bom/internal/errors/redteam"
	redteamclient "github.com/snyk/cli-extension-ai-bom/internal/services/red-team-client"
	redteamclientmock "github.com/snyk/cli-extension-ai-bom/internal/services/red-team-client/mock"
	"github.com/snyk/cli-extension-ai-bom/mocks/frameworkmock"
)

const (
	experimentalKey = "experimental"
	organizationKey = "organization"
	testOrgID       = "test-org"
	validScanID     = "12345678-90ab-cdef-1234-567890abcdef"
)

func TestRunRedTeamGetWorkflow_HappyPath(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(organizationKey, testOrgID)
	ictx.GetConfiguration().Set("id", validScanID)

	expectedResults := redteamclient.GetAIVulnerabilitiesResponseData{
		ID: validScanID,
		Results: []redteamclient.AIVulnerability{
			{
				ID:       "vuln-1",
				Severity: "high",
				URL:      "https://example.com/api",
				Definition: redteamclient.AIVulnerabilityDefinition{
					ID:   "prompt-injection",
					Name: "Prompt Injection",
				},
			},
		},
	}

	mockClient := &redteamclientmock.MockRedTeamClient{
		ScanResults: expectedResults,
	}

	results, err := redteamget.RunRedTeamGetWorkflow(ictx, mockClient)
	require.NoError(t, err)
	require.Len(t, results, 1)

	payload, ok := results[0].GetPayload().([]byte)
	require.True(t, ok)

	var data redteamclient.GetAIVulnerabilitiesResponseData
	err = json.Unmarshal(payload, &data)
	require.NoError(t, err)
	require.Equal(t, validScanID, data.ID)
	require.Len(t, data.Results, 1)
	require.Equal(t, "vuln-1", data.Results[0].ID)
	require.Equal(t, "high", data.Results[0].Severity)
}

func TestRunRedTeamGetWorkflow_MissingID(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(organizationKey, testOrgID)

	mockClient := &redteamclientmock.MockRedTeamClient{}

	_, err := redteamget.RunRedTeamGetWorkflow(ictx, mockClient)
	require.Error(t, err)
	require.Contains(t, err.Error(), "No scan ID specified")
}

func TestRunRedTeamGetWorkflow_InvalidUUID(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(organizationKey, testOrgID)
	ictx.GetConfiguration().Set("id", "not-a-valid-uuid")

	mockClient := &redteamclientmock.MockRedTeamClient{}

	_, err := redteamget.RunRedTeamGetWorkflow(ictx, mockClient)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Scan ID is not a valid UUID")
}

func TestRunRedTeamGetWorkflow_MissingExperimentalFlag(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(organizationKey, testOrgID)
	ictx.GetConfiguration().Set("id", validScanID)

	mockClient := &redteamclientmock.MockRedTeamClient{}

	_, err := redteamget.RunRedTeamGetWorkflow(ictx, mockClient)
	require.Error(t, err)
}

func TestRunRedTeamGetWorkflow_ScanNotFound(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(organizationKey, testOrgID)
	ictx.GetConfiguration().Set("id", validScanID)

	mockClient := &redteamclientmock.MockRedTeamClient{
		ResultsError: redteam_errors.NewNotFoundError("This scan was not found"),
	}

	_, err := redteamget.RunRedTeamGetWorkflow(ictx, mockClient)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}
