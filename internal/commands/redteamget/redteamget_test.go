package redteamget_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"

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

func TestRunRedTeamGetWorkflow_MissingOrgID(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(configuration.ORGANIZATION, "")
	ictx.GetConfiguration().Set("id", validScanID)

	mockClient := &redteamclientmock.MockRedTeamClient{}

	_, err := redteamget.RunRedTeamGetWorkflow(ictx, mockClient)
	require.Error(t, err)
}

func newHTMLMockClient() *redteamclientmock.MockRedTeamClient {
	return &redteamclientmock.MockRedTeamClient{
		ScanResults: redteamclient.GetAIVulnerabilitiesResponseData{
			ID: "report-get-123",
			Results: []redteamclient.AIVulnerability{
				{
					ID:       "vuln-get-001",
					Severity: "high",
					URL:      "https://example.com/api/chat",
					Definition: redteamclient.AIVulnerabilityDefinition{
						ID:          "system_prompt_exfiltration",
						Name:        "System Prompt Exfiltration",
						Description: "The system prompt was exfiltrated.",
					},
					Evidence: redteamclient.AIVulnerabilityEvidence{
						Type: "raw",
						Content: redteamclient.AIVulnerabilityEvidenceContent{
							Reason: "test reason",
						},
					},
				},
			},
		},
	}
}

func TestRunRedTeamGetWorkflow_HTMLOutput(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(organizationKey, testOrgID)
	ictx.GetConfiguration().Set("id", validScanID)
	ictx.GetConfiguration().Set("html", true)

	results, err := redteamget.RunRedTeamGetWorkflow(ictx, newHTMLMockClient())
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "text/html", results[0].GetContentType())

	payload, ok := results[0].GetPayload().([]byte)
	require.True(t, ok)
	html := string(payload)
	assert.Contains(t, html, "<!doctype html>")
	assert.Contains(t, html, "report-get-123")
	assert.Contains(t, html, "System Prompt Exfiltration")
}

func TestRunRedTeamGetWorkflow_HTMLFileOutput(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(organizationKey, testOrgID)
	ictx.GetConfiguration().Set("id", validScanID)

	tmpFile := t.TempDir() + "/report.html"
	ictx.GetConfiguration().Set("html-file-output", tmpFile)

	results, err := redteamget.RunRedTeamGetWorkflow(ictx, newHTMLMockClient())
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "application/json", results[0].GetContentType())

	fileContent, readErr := os.ReadFile(tmpFile)
	require.NoError(t, readErr)
	html := string(fileContent)
	assert.Contains(t, html, "<!doctype html>")
	assert.Contains(t, html, "report-get-123")
	assert.Contains(t, html, "System Prompt Exfiltration")
}

func TestRunRedTeamGetWorkflow_HTMLFileOutputWithHTMLFlag(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(organizationKey, testOrgID)
	ictx.GetConfiguration().Set("id", validScanID)

	tmpFile := t.TempDir() + "/report.html"
	ictx.GetConfiguration().Set("html-file-output", tmpFile)
	ictx.GetConfiguration().Set("html", true)

	results, err := redteamget.RunRedTeamGetWorkflow(ictx, newHTMLMockClient())
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "text/html", results[0].GetContentType())

	stdoutPayload, ok := results[0].GetPayload().([]byte)
	require.True(t, ok)
	assert.Contains(t, string(stdoutPayload), "report-get-123")

	fileContent, readErr := os.ReadFile(tmpFile)
	require.NoError(t, readErr)
	html := string(fileContent)
	assert.Contains(t, html, "<!doctype html>")
	assert.Contains(t, html, "System Prompt Exfiltration")
}

func TestRunRedTeamGetWorkflow_HTMLOutputWithEmptyResults(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(organizationKey, testOrgID)
	ictx.GetConfiguration().Set("id", validScanID)
	ictx.GetConfiguration().Set("html", true)

	mockClient := &redteamclientmock.MockRedTeamClient{
		ScanResults: redteamclient.GetAIVulnerabilitiesResponseData{
			ID:      "report-empty",
			Results: []redteamclient.AIVulnerability{},
		},
	}

	results, err := redteamget.RunRedTeamGetWorkflow(ictx, mockClient)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "text/html", results[0].GetContentType())

	payload, ok := results[0].GetPayload().([]byte)
	require.True(t, ok)
	html := string(payload)
	assert.Contains(t, html, "report-empty")
	assert.Contains(t, html, "No issues found")
}

func TestRunRedTeamGetWorkflow_ServerError(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(organizationKey, testOrgID)
	ictx.GetConfiguration().Set("id", validScanID)

	mockClient := &redteamclientmock.MockRedTeamClient{
		ResultsError: redteam_errors.NewServerError("internal server error"),
	}

	_, err := redteamget.RunRedTeamGetWorkflow(ictx, mockClient)
	require.Error(t, err)
	require.Contains(t, err.Error(), "internal server error")
}
