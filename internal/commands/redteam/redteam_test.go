package redteam_test

import (
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"

	"github.com/snyk/cli-extension-ai-bom/internal/commands/redteam"
	redteam_errors "github.com/snyk/cli-extension-ai-bom/internal/errors/redteam"
	redteamclient "github.com/snyk/cli-extension-ai-bom/internal/services/red-team-client"
	redteamclientmock "github.com/snyk/cli-extension-ai-bom/internal/services/red-team-client/mock"
	"github.com/snyk/cli-extension-ai-bom/mocks/frameworkmock"
)

const (
	experimentalKey       = "experimental"
	organizationKey       = "organization"
	testOrgID             = "test-org"
	configFlag            = "config"
	redteamTestConfigFile = "testdata/redteam.yaml"
)

func TestRunRedTeamWorkflow_HappyPath(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(organizationKey, testOrgID)
	ictx.GetConfiguration().Set(configFlag, redteamTestConfigFile)

	mockClient := &redteamclientmock.MockRedTeamClient{
		PollingScans: []redteamclient.AIScan{
			{ID: "test-scan-id", Status: redteamclient.AIScanStatusStarted},
			{ID: "test-scan-id", Status: redteamclient.AIScanStatusCompleted},
		},
		ScanResults: redteamclient.GetAIVulnerabilitiesResponseData{
			ID: uuid.New().String(),
			Results: []redteamclient.AIVulnerability{
				{
					ID:  "test-vulnerability-id",
					URL: "test-vulnerability-url",
				},
			},
		},
	}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam"}
	defer func() { os.Args = originalArgs }()

	results, err := redteam.RunRedTeamWorkflow(ictx, mockClient)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "application/json", results[0].GetContentType())
	payload, _ := results[0].GetPayload().([]byte)
	assert.Contains(t, string(payload), "test-vulnerability-id")
	assert.Contains(t, string(payload), "test-vulnerability-url")
}

func TestRunRedTeamWorkflow_ExperimentalFlagRequired(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, false)

	mockClient := &redteamclientmock.MockRedTeamClient{
		PollingScans: []redteamclient.AIScan{
			{ID: "test-scan-id", Status: redteamclient.AIScanStatusCompleted},
		},
	}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam"}
	defer func() { os.Args = originalArgs }()

	_, err := redteam.RunRedTeamWorkflow(ictx, mockClient)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "experimental")
}

func TestRunRedTeamWorkflow_NoOrgID(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(configuration.ORGANIZATION, "")

	mockClient := &redteamclientmock.MockRedTeamClient{
		PollingScans: []redteamclient.AIScan{
			{ID: "test-scan-id", Status: redteamclient.AIScanStatusCompleted},
		},
	}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam"}
	defer func() { os.Args = originalArgs }()

	_, err := redteam.RunRedTeamWorkflow(ictx, mockClient)
	require.Error(t, err)
	assert.NotNil(t, err)
}

func TestHandleRunScanCommand_ConfigFileNotFound(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(organizationKey, testOrgID)
	ictx.GetConfiguration().Set(configFlag, "nonexistent-config.yaml")

	mockClient := &redteamclientmock.MockRedTeamClient{
		PollingScans: []redteamclient.AIScan{
			{ID: "test-scan-id", Status: redteamclient.AIScanStatusCompleted},
		},
	}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam"}
	defer func() { os.Args = originalArgs }()

	results, err := redteam.RunRedTeamWorkflow(ictx, mockClient)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "text/plain", results[0].GetContentType())

	payload, ok := results[0].GetPayload().([]byte)
	require.True(t, ok, "expected payload to be []byte")
	content := string(payload)
	assert.Contains(t, content, "Configuration file not found")
	assert.Contains(t, content, "redteam.yaml")
}

func TestHandleRunScanCommand_InvalidYAML(t *testing.T) {
	configContent := `
target:
  name: "Test Target"
  type: api

  ---- invalid yaml syntax ----
`
	err := os.WriteFile("test-invalid.yaml", []byte(configContent), 0o600)
	require.NoError(t, err)
	defer os.Remove("test-invalid.yaml")

	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(organizationKey, testOrgID)
	ictx.GetConfiguration().Set(configFlag, "test-invalid.yaml")

	mockClient := &redteamclientmock.MockRedTeamClient{
		PollingScans: []redteamclient.AIScan{
			{ID: "test-scan-id", Status: redteamclient.AIScanStatusCompleted},
		},
	}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam"}
	defer func() { os.Args = originalArgs }()

	results, err := redteam.RunRedTeamWorkflow(ictx, mockClient)
	require.NoError(t, err)
	payload, _ := results[0].GetPayload().([]byte)
	assert.Contains(t, string(payload), "Configuration file in invalid")
}

func TestHandleRunScanCommand_ValidationFailure(t *testing.T) {
	tests := []struct {
		name          string
		configContent string
		fileName      string
	}{
		{
			name: "MissingRequiredFields",
			configContent: `
target:
  name: "Test Target"
  type: api
`,
			fileName: "test-validation.yaml",
		},
		{
			name: "InvalidTargetType",
			configContent: `
target:
  name: "Test Target"
  type: invalid_type
  settings:
    url: "https://example.com"
    response_selector: "response"
    request_body_template: "{\"message\": \"test\"}"
`,
			fileName: "test-invalid-type.yaml",
		},
		{
			name: "InvalidURL",
			configContent: `
target:
  name: "Test Target"
  type: api
  settings:
    url: "not-a-valid-url"
    response_selector: "response"
    request_body_template: "{\"message\": \"test\"}"
`,
			fileName: "test-invalid-url.yaml",
		},
		{
			name: "InvalidJSON",
			configContent: `
target:
  name: "Test Target"
  type: api
  settings:
    url: "https://example.com"
    response_selector: "response"
    request_body_template: "not valid json"
`,
			fileName: "test-invalid-json.yaml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := os.WriteFile(tt.fileName, []byte(tt.configContent), 0o600)
			require.NoError(t, err)
			defer os.Remove(tt.fileName)

			ictx := frameworkmock.NewMockInvocationContext(t)
			ictx.GetConfiguration().Set(experimentalKey, true)
			ictx.GetConfiguration().Set(organizationKey, testOrgID)
			ictx.GetConfiguration().Set(configFlag, tt.fileName)

			mockClient := &redteamclientmock.MockRedTeamClient{
				PollingScans: []redteamclient.AIScan{
					{ID: "test-scan-id", Status: redteamclient.AIScanStatusCompleted},
				},
			}

			originalArgs := os.Args
			os.Args = []string{"snyk", "redteam"}
			defer func() { os.Args = originalArgs }()

			_, err = redteam.RunRedTeamWorkflow(ictx, mockClient)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "validation")
		})
	}
}

func TestHandleRunScanCommand_ValidateTargetError(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(organizationKey, testOrgID)
	ictx.GetConfiguration().Set(configFlag, redteamTestConfigFile)

	mockClient := &redteamclientmock.MockRedTeamClient{
		CreateError: redteam_errors.NewServerError("test error"),
		PollingScans: []redteamclient.AIScan{
			{ID: "test-scan-id", Status: redteamclient.AIScanStatusCompleted},
		},
	}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam"}
	defer func() { os.Args = originalArgs }()

	_, err := redteam.RunRedTeamWorkflow(ictx, mockClient)
	require.Error(t, err)
}

func TestHandleRunScanCommand_CustomConfigPathDoesNotExist(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(organizationKey, testOrgID)
	ictx.GetConfiguration().Set(configFlag, "path-that-does-not-exist/test-custom-config.yaml")

	mockClient := &redteamclientmock.MockRedTeamClient{
		PollingScans: []redteamclient.AIScan{
			{ID: "test-scan-id", Status: redteamclient.AIScanStatusCompleted},
		},
	}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam"}
	defer func() { os.Args = originalArgs }()

	results, err := redteam.RunRedTeamWorkflow(ictx, mockClient)
	require.NoError(t, err)
	payload, _ := results[0].GetPayload().([]byte)
	assert.Contains(t, string(payload), "Configuration file not found")
}

func TestHandleRunScanCommand_CustomConfig(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(organizationKey, testOrgID)
	ictx.GetConfiguration().Set(configFlag, "testdata/custom/path/test-custom-config.yaml")

	mockClient := &redteamclientmock.MockRedTeamClient{
		PollingScans: []redteamclient.AIScan{
			{ID: "test-scan-id", Status: redteamclient.AIScanStatusCompleted},
		},
	}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam"}
	defer func() { os.Args = originalArgs }()

	_, err := redteam.RunRedTeamWorkflow(ictx, mockClient)
	assert.NoError(t, err)
}

func TestHandleRunScanCommand_ScanError(t *testing.T) {
	tests := []struct {
		name               string
		errorCode          string
		errorMessage       string
		expectedErrorText  []string
		expectedUnwrapText string
	}{
		{
			name:               "scan error",
			errorCode:          "scan_error",
			errorMessage:       "Scan failed due to internal error",
			expectedErrorText:  []string{"Red teaming scan (ID: test-scan-id) failed"},
			expectedUnwrapText: "Unspecified Error",
		},
		{
			name:               "network error",
			errorCode:          "network_error",
			errorMessage:       "Connection timeout",
			expectedErrorText:  []string{"Connection timeout"},
			expectedUnwrapText: "Client request cannot be processed",
		},
		{
			name:               "context error",
			errorCode:          "context_error",
			errorMessage:       "Invalid context",
			expectedErrorText:  []string{"Invalid context"},
			expectedUnwrapText: "Client request cannot be processed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ictx := frameworkmock.NewMockInvocationContext(t)
			ictx.GetConfiguration().Set(experimentalKey, true)
			ictx.GetConfiguration().Set(organizationKey, testOrgID)
			ictx.GetConfiguration().Set(configFlag, redteamTestConfigFile)

			mockClient := &redteamclientmock.MockRedTeamClient{
				PollingScans: []redteamclient.AIScan{
					{ID: "test-scan-id", Status: redteamclient.AIScanStatusStarted},
					{
						ID:     "test-scan-id",
						Status: redteamclient.AIScanStatusFailed,
						Feedback: redteamclient.AIScanFeedback{
							Error: []redteamclient.AIScanFeedbackIssue{
								{
									Code:    tt.errorCode,
									Message: tt.errorMessage,
								},
							},
						},
					},
				},
			}

			originalArgs := os.Args
			os.Args = []string{"snyk", "redteam"}
			defer func() { os.Args = originalArgs }()

			_, err := redteam.RunRedTeamWorkflow(ictx, mockClient)
			require.Error(t, err)

			for _, expectedText := range tt.expectedErrorText {
				assert.Contains(t, err.Error(), expectedText)
			}

			var redTeamErr *redteam_errors.RedTeamError
			require.True(t, errors.As(err, &redTeamErr), "error should be a RedTeamError")
			unwrappedErr := errors.Unwrap(redTeamErr)
			require.NotNil(t, unwrappedErr, "error should have an underlying error")
			assert.Contains(t, unwrappedErr.Error(), tt.expectedUnwrapText)
		})
	}
}

func TestHandleRunScanCommand_ScanErrorWithVulnerabilities_ShowsGetHint(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(organizationKey, testOrgID)
	ictx.GetConfiguration().Set(configFlag, redteamTestConfigFile)

	ui, ok := ictx.GetUserInterface().(*mocks.MockUserInterface)
	require.True(t, ok, "UI should be a mock")
	ui.EXPECT().Output(gomock.Any()).Return(nil).AnyTimes()

	criticals, highs, mediums, lows := 1, 2, 0, 0

	mockClient := &redteamclientmock.MockRedTeamClient{
		PollingScans: []redteamclient.AIScan{
			{ID: "test-scan-id", Status: redteamclient.AIScanStatusStarted},
			{
				ID:        "test-scan-id",
				Status:    redteamclient.AIScanStatusFailed,
				Criticals: &criticals,
				Highs:     &highs,
				Mediums:   &mediums,
				Lows:      &lows,
				Feedback: redteamclient.AIScanFeedback{
					Error: []redteamclient.AIScanFeedbackIssue{
						{
							Code:    "too_many_failures",
							Message: "Multiple consecutive failures during scan",
						},
					},
				},
			},
		},
	}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam"}
	defer func() { os.Args = originalArgs }()

	_, err := redteam.RunRedTeamWorkflow(ictx, mockClient)
	require.Error(t, err)

	assert.Contains(t, err.Error(), "Partial results are available (3 found before failure)")
	assert.Contains(t, err.Error(), "snyk redteam --experimental get --id=test-scan-id")
}

func TestHandleRunScanCommand_ScanErrorWithoutVulnerabilities_NoGetHint(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(organizationKey, testOrgID)
	ictx.GetConfiguration().Set(configFlag, redteamTestConfigFile)

	mockClient := &redteamclientmock.MockRedTeamClient{
		PollingScans: []redteamclient.AIScan{
			{ID: "test-scan-id", Status: redteamclient.AIScanStatusStarted},
			{
				ID:     "test-scan-id",
				Status: redteamclient.AIScanStatusFailed,
				Feedback: redteamclient.AIScanFeedback{
					Error: []redteamclient.AIScanFeedbackIssue{
						{
							Code:    "network_error",
							Message: "Connection timeout",
						},
					},
				},
			},
		},
	}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam"}
	defer func() { os.Args = originalArgs }()

	_, err := redteam.RunRedTeamWorkflow(ictx, mockClient)
	require.Error(t, err)

	assert.NotContains(t, err.Error(), "Partial results are available")
	assert.NotContains(t, err.Error(), "get --id=")
}

func setupMockRedTeamClient() *redteamclientmock.MockRedTeamClient {
	return &redteamclientmock.MockRedTeamClient{
		PollingScans: []redteamclient.AIScan{
			{ID: "test-scan-id", Status: redteamclient.AIScanStatusStarted},
			{ID: "test-scan-id", Status: redteamclient.AIScanStatusCompleted},
		},
		ScanResults: redteamclient.GetAIVulnerabilitiesResponseData{
			ID: uuid.New().String(),
			Results: []redteamclient.AIVulnerability{
				{
					ID:  "test-vulnerability-id",
					URL: "test-vulnerability-url",
				},
			},
		},
	}
}

func TestRunRedTeamWorkflowWithScanningAgent_HappyPath(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(organizationKey, testOrgID)
	ictx.GetConfiguration().Set(configFlag, redteamTestConfigFile)

	mockClient := setupMockRedTeamClient()

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam"}
	defer func() { os.Args = originalArgs }()

	_, err := redteam.RunRedTeamWorkflow(ictx, mockClient)
	require.NoError(t, err)
}

func TestRunRedTeamWorkflowWithScanningAgent_InvalidScanningAgentID(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(organizationKey, testOrgID)
	ictx.GetConfiguration().Set(configFlag, "testdata/redteam-invalid-scanning-agent-id.yaml")

	mockClient := setupMockRedTeamClient()

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam"}
	defer func() { os.Args = originalArgs }()

	_, err := redteam.RunRedTeamWorkflow(ictx, mockClient)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validation")
}

func TestRunRedTeamWorkflowWithScanningAgentOverride_HappyPath(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(organizationKey, testOrgID)
	ictx.GetConfiguration().Set(configFlag, redteamTestConfigFile)
	testUUID := "d587a7bd-16af-403a-bc1e-9103b3a42e36"
	ictx.GetConfiguration().Set("scanning-agent-id", testUUID)

	mockClient := setupMockRedTeamClient()

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam"}
	defer func() { os.Args = originalArgs }()

	_, err := redteam.RunRedTeamWorkflow(ictx, mockClient)
	require.NoError(t, err)

	clientConfig, _, err := redteam.LoadAndValidateConfig(ictx.GetEnhancedLogger(), ictx.GetConfiguration())
	require.NoError(t, err)
	assert.Equal(t, testUUID, clientConfig.Options.ScanningAgent)
}

func TestRunRedTeamWorkflowWithScanningAgentOverride_InvalidScanningAgentID(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(organizationKey, testOrgID)
	ictx.GetConfiguration().Set(configFlag, redteamTestConfigFile)
	ictx.GetConfiguration().Set("scanning-agent-id", "test-scanning-agent-id")

	mockClient := setupMockRedTeamClient()

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam"}
	defer func() { os.Args = originalArgs }()

	_, err := redteam.RunRedTeamWorkflow(ictx, mockClient)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Scanning agent ID is not a valid UUID")
}

func TestRunRedTeamWorkflow_HTMLOutput(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(organizationKey, testOrgID)
	ictx.GetConfiguration().Set(configFlag, redteamTestConfigFile)
	ictx.GetConfiguration().Set("html", true)

	mockClient := &redteamclientmock.MockRedTeamClient{
		PollingScans: []redteamclient.AIScan{
			{ID: "test-scan-id", Status: redteamclient.AIScanStatusStarted},
			{ID: "test-scan-id", Status: redteamclient.AIScanStatusCompleted},
		},
		ScanResults: redteamclient.GetAIVulnerabilitiesResponseData{
			ID: "report-123",
			Results: []redteamclient.AIVulnerability{
				{
					ID: "vuln-001",
					Definition: redteamclient.AIVulnerabilityDefinition{
						ID:          "capability_extraction",
						Name:        "Capability extraction",
						Description: "Test description",
					},
					Tags:     []string{"framework: OWASP, LLM01 - Prompt Injection"},
					Severity: "high",
					URL:      "https://example.com/api/chat",
					Turns: []redteamclient.Turn{
						{
							Request:  strPtr("test request"),
							Response: strPtr("test response"),
						},
					},
					Evidence: redteamclient.AIVulnerabilityEvidence{
						Type: "json",
						Content: redteamclient.AIVulnerabilityEvidenceContent{
							Reason: "test reason",
						},
					},
				},
			},
		},
	}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam", "--html"}
	defer func() { os.Args = originalArgs }()

	results, err := redteam.RunRedTeamWorkflow(ictx, mockClient)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "text/html", results[0].GetContentType())

	payload, ok := results[0].GetPayload().([]byte)
	require.True(t, ok)
	html := string(payload)
	assert.Contains(t, html, "<!doctype html>")
	assert.Contains(t, html, "report-123")
	assert.Contains(t, html, "vuln-001")
	assert.Contains(t, html, "Capability extraction")
	assert.Contains(t, html, "https://example.com/api/chat")
}

func TestRunRedTeamWorkflow_HTMLOutputWithEmptyResults(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(organizationKey, testOrgID)
	ictx.GetConfiguration().Set(configFlag, redteamTestConfigFile)
	ictx.GetConfiguration().Set("html", true)

	mockClient := &redteamclientmock.MockRedTeamClient{
		PollingScans: []redteamclient.AIScan{
			{ID: "test-scan-id", Status: redteamclient.AIScanStatusCompleted},
		},
		ScanResults: redteamclient.GetAIVulnerabilitiesResponseData{
			ID:      "report-empty",
			Results: []redteamclient.AIVulnerability{},
		},
	}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam", "--html"}
	defer func() { os.Args = originalArgs }()

	results, err := redteam.RunRedTeamWorkflow(ictx, mockClient)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "text/html", results[0].GetContentType())

	payload, ok := results[0].GetPayload().([]byte)
	require.True(t, ok)
	html := string(payload)
	assert.Contains(t, html, "report-empty")
	assert.Contains(t, html, "No issues found")
}

func TestRunRedTeamWorkflow_HTMLOutputWithoutTags(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(organizationKey, testOrgID)
	ictx.GetConfiguration().Set(configFlag, redteamTestConfigFile)
	ictx.GetConfiguration().Set("html", true)

	mockClient := &redteamclientmock.MockRedTeamClient{
		PollingScans: []redteamclient.AIScan{
			{ID: "test-scan-id", Status: redteamclient.AIScanStatusStarted},
			{ID: "test-scan-id", Status: redteamclient.AIScanStatusCompleted},
		},
		ScanResults: redteamclient.GetAIVulnerabilitiesResponseData{
			ID: "report-no-tags",
			Results: []redteamclient.AIVulnerability{
				{
					ID: "vuln-no-tags",
					Definition: redteamclient.AIVulnerabilityDefinition{
						ID:   "test_def",
						Name: "Test Definition",
					},
					Severity: "medium",
					URL:      "https://example.com",
				},
			},
		},
	}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam", "--html"}
	defer func() { os.Args = originalArgs }()

	results, err := redteam.RunRedTeamWorkflow(ictx, mockClient)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "text/html", results[0].GetContentType())

	payload, ok := results[0].GetPayload().([]byte)
	require.True(t, ok)
	html := string(payload)
	assert.Contains(t, html, "vuln-no-tags")
	assert.Contains(t, html, "Test Definition")
}

func TestRunRedTeamWorkflow_HTMLFileOutput(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(organizationKey, testOrgID)
	ictx.GetConfiguration().Set(configFlag, redteamTestConfigFile)

	tmpFile := t.TempDir() + "/report.html"
	ictx.GetConfiguration().Set("html-file-output", tmpFile)

	mockClient := &redteamclientmock.MockRedTeamClient{
		PollingScans: []redteamclient.AIScan{
			{ID: "test-scan-id", Status: redteamclient.AIScanStatusCompleted},
		},
		ScanResults: redteamclient.GetAIVulnerabilitiesResponseData{
			ID: "report-file",
			Results: []redteamclient.AIVulnerability{
				{
					ID: "vuln-file-001",
					Definition: redteamclient.AIVulnerabilityDefinition{
						ID:   "test_def",
						Name: "File Output Test",
					},
					Severity: "high",
					URL:      "https://example.com/api",
				},
			},
		},
	}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam", "--html-file-output", tmpFile}
	defer func() { os.Args = originalArgs }()

	results, err := redteam.RunRedTeamWorkflow(ictx, mockClient)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "application/json", results[0].GetContentType())

	fileContent, readErr := os.ReadFile(tmpFile)
	require.NoError(t, readErr)
	html := string(fileContent)
	assert.Contains(t, html, "<!doctype html>")
	assert.Contains(t, html, "vuln-file-001")
	assert.Contains(t, html, "File Output Test")
}

func TestRunRedTeamWorkflow_HTMLFileOutputWithHTMLFlag(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(organizationKey, testOrgID)
	ictx.GetConfiguration().Set(configFlag, redteamTestConfigFile)

	tmpFile := t.TempDir() + "/report.html"
	ictx.GetConfiguration().Set("html-file-output", tmpFile)
	ictx.GetConfiguration().Set("html", true)

	mockClient := &redteamclientmock.MockRedTeamClient{
		PollingScans: []redteamclient.AIScan{
			{ID: "test-scan-id", Status: redteamclient.AIScanStatusCompleted},
		},
		ScanResults: redteamclient.GetAIVulnerabilitiesResponseData{
			ID: "report-both",
			Results: []redteamclient.AIVulnerability{
				{
					ID: "vuln-both-001",
					Definition: redteamclient.AIVulnerabilityDefinition{
						ID:   "test_def",
						Name: "Both Output Test",
					},
					Severity: "medium",
					URL:      "https://example.com/api",
				},
			},
		},
	}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam", "--html", "--html-file-output", tmpFile}
	defer func() { os.Args = originalArgs }()

	results, err := redteam.RunRedTeamWorkflow(ictx, mockClient)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "text/html", results[0].GetContentType())

	stdoutPayload, ok := results[0].GetPayload().([]byte)
	require.True(t, ok)
	assert.Contains(t, string(stdoutPayload), "vuln-both-001")

	fileContent, readErr := os.ReadFile(tmpFile)
	require.NoError(t, readErr)
	html := string(fileContent)
	assert.Contains(t, html, "<!doctype html>")
	assert.Contains(t, html, "vuln-both-001")
	assert.Contains(t, html, "Both Output Test")
}

func strPtr(s string) *string {
	return &s
}

func TestRunRedTeamWorkflow_VulnerabilitiesFoundDuringPolling(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(organizationKey, testOrgID)
	ictx.GetConfiguration().Set(configFlag, redteamTestConfigFile)

	ui, ok := ictx.GetUserInterface().(*mocks.MockUserInterface)
	require.True(t, ok, "UI should be a mock")
	ui.EXPECT().Output(gomock.Any()).DoAndReturn(func(output string) error {
		assert.Contains(t, output, "New vulnerabilities found. Total:")
		assert.Contains(t, output, "1 Critical")
		assert.Contains(t, output, "2 High")
		assert.Contains(t, output, "3 Medium")
		assert.Contains(t, output, "4 Low")
		return nil
	}).Times(1)

	done1, total1 := 5, 10
	done2, total2 := 10, 10
	criticals, highs, mediums, lows := 1, 2, 3, 4

	mockClient := &redteamclientmock.MockRedTeamClient{
		PollingScans: []redteamclient.AIScan{
			{
				ID:     "test-scan-id",
				Status: redteamclient.AIScanStatusStarted,
				Feedback: redteamclient.AIScanFeedback{
					Status: &redteamclient.AIScanFeedbackStatus{Done: &done1, Total: &total1},
				},
				Criticals: &criticals,
				Highs:     &highs,
				Mediums:   &mediums,
				Lows:      &lows,
			},
			{
				ID:     "test-scan-id",
				Status: redteamclient.AIScanStatusCompleted,
				Feedback: redteamclient.AIScanFeedback{
					Status: &redteamclient.AIScanFeedbackStatus{Done: &done2, Total: &total2},
				},
				Criticals: &criticals,
				Highs:     &highs,
				Mediums:   &mediums,
				Lows:      &lows,
			},
		},
		ScanResults: redteamclient.GetAIVulnerabilitiesResponseData{
			ID: uuid.New().String(),
			Results: []redteamclient.AIVulnerability{
				{
					ID:  "test-vulnerability-id",
					URL: "test-vulnerability-url",
				},
			},
		},
	}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam"}
	defer func() { os.Args = originalArgs }()

	results, err := redteam.RunRedTeamWorkflow(ictx, mockClient)
	require.NoError(t, err)
	assert.Len(t, results, 1)
}
