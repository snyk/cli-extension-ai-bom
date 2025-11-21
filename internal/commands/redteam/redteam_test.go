package redteam_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/cli-extension-ai-bom/internal/commands/redteam"
	redteam_errors "github.com/snyk/cli-extension-ai-bom/internal/errors/redteam"
	redteamclient "github.com/snyk/cli-extension-ai-bom/internal/services/red-team-client"
	"github.com/snyk/cli-extension-ai-bom/mocks/frameworkmock"
)

const (
	experimentalKey = "experimental"
	testOrgID       = "test-org"
	configFlag      = "config"
)

// MockRedTeamClient implements the RedTeamClient interface for testing.
type MockRedTeamClient struct {
	scanData     []redteamclient.AIScan
	scanResults  redteamclient.GetAIVulnerabilitiesResponseData
	createError  *redteam_errors.RedTeamError
	getError     *redteam_errors.RedTeamError
	resultsError *redteam_errors.RedTeamError
	getScanCalls int
	pollingScans []redteamclient.AIScan
}

func (m *MockRedTeamClient) CreateScan(_ context.Context, _ string, _ *redteamclient.RedTeamConfig) (string, *redteam_errors.RedTeamError) {
	if m.createError != nil {
		return "", m.createError
	}
	return "test-scan-id", nil
}

func (m *MockRedTeamClient) GetScan(_ context.Context, _, _ string) (*redteamclient.AIScan, *redteam_errors.RedTeamError) {
	if m.getError != nil {
		return nil, m.getError
	}

	if len(m.pollingScans) > 0 {
		if m.getScanCalls < len(m.pollingScans) {
			scan := m.pollingScans[m.getScanCalls]
			m.getScanCalls++
			return &scan, nil
		}
		return &m.pollingScans[len(m.pollingScans)-1], nil
	}

	if len(m.scanData) > 0 {
		return &m.scanData[0], nil
	}

	return &redteamclient.AIScan{
		ID:     "test-scan-id",
		Status: redteamclient.AIScanStatusCompleted,
	}, nil
}

func (m *MockRedTeamClient) GetScanResults(_ context.Context, _, _ string) (redteamclient.GetAIVulnerabilitiesResponseData, *redteam_errors.RedTeamError) {
	if m.resultsError != nil {
		return redteamclient.GetAIVulnerabilitiesResponseData{}, m.resultsError
	}
	return m.scanResults, nil
}

func TestRunRedTeamWorkflow_HappyPath(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set("organization", testOrgID)
	ictx.GetConfiguration().Set("config", "testdata/redteam.yaml")

	mockClient := &MockRedTeamClient{
		pollingScans: []redteamclient.AIScan{
			{ID: "test-scan-id", Status: redteamclient.AIScanStatusStarted},
			{ID: "test-scan-id", Status: redteamclient.AIScanStatusCompleted},
		},
		scanResults: redteamclient.GetAIVulnerabilitiesResponseData{
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

	mockClient := &MockRedTeamClient{
		pollingScans: []redteamclient.AIScan{
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

	mockClient := &MockRedTeamClient{
		pollingScans: []redteamclient.AIScan{
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
	ictx.GetConfiguration().Set(configuration.ORGANIZATION, testOrgID)
	ictx.GetConfiguration().Set(configFlag, "nonexistent-config.yaml")

	mockClient := &MockRedTeamClient{
		pollingScans: []redteamclient.AIScan{
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
	ictx.GetConfiguration().Set(configuration.ORGANIZATION, testOrgID)
	ictx.GetConfiguration().Set(configFlag, "test-invalid.yaml")

	mockClient := &MockRedTeamClient{
		pollingScans: []redteamclient.AIScan{
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
			ictx.GetConfiguration().Set(configuration.ORGANIZATION, testOrgID)
			ictx.GetConfiguration().Set(configFlag, tt.fileName)

			mockClient := &MockRedTeamClient{
				pollingScans: []redteamclient.AIScan{
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
	ictx.GetConfiguration().Set(configuration.ORGANIZATION, testOrgID)
	ictx.GetConfiguration().Set(configFlag, "testdata/redteam.yaml")

	mockClient := &MockRedTeamClient{
		createError: redteam_errors.NewServerError("test error"),
		pollingScans: []redteamclient.AIScan{
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
	ictx.GetConfiguration().Set(configuration.ORGANIZATION, testOrgID)
	ictx.GetConfiguration().Set(configFlag, "path-that-does-not-exist/test-custom-config.yaml")

	mockClient := &MockRedTeamClient{
		pollingScans: []redteamclient.AIScan{
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
	ictx.GetConfiguration().Set(configuration.ORGANIZATION, testOrgID)
	ictx.GetConfiguration().Set(configFlag, "testdata/custom/path/test-custom-config.yaml")

	mockClient := &MockRedTeamClient{
		pollingScans: []redteamclient.AIScan{
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
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(configuration.ORGANIZATION, testOrgID)
	ictx.GetConfiguration().Set(configFlag, "testdata/redteam.yaml")

	mockClient := &MockRedTeamClient{
		pollingScans: []redteamclient.AIScan{
			{ID: "test-scan-id", Status: redteamclient.AIScanStatusStarted},
			{
				ID:     "test-scan-id",
				Status: redteamclient.AIScanStatusFailed,
				Feedback: redteamclient.AIScanFeedback{
					Error: []redteamclient.AIScanFeedbackIssue{
						{
							Code:    "scan_error",
							Message: "Scan failed due to internal error",
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
	assert.Contains(t, err.Error(), "type: scan_error, message: Scan failed due to internal error")

	var redTeamErr *redteam_errors.RedTeamError
	require.True(t, errors.As(err, &redTeamErr), "error should be a RedTeamError")
	unwrappedErr := errors.Unwrap(redTeamErr)
	require.NotNil(t, unwrappedErr, "error should have an underlying error")
	assert.Contains(t, unwrappedErr.Error(), "test-scan-id")
	assert.Contains(t, unwrappedErr.Error(), "Red Teaming scan (ID: test-scan-id) failed")
}
