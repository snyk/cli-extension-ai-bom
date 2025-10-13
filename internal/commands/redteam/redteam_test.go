package redteam_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	snyk_common_errors "github.com/snyk/error-catalog-golang-public/snyk"
	errors "github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/cli-extension-ai-bom/internal/commands/redteam"
	redteamclient "github.com/snyk/cli-extension-ai-bom/internal/services/red-team-client"
	"github.com/snyk/cli-extension-ai-bom/mocks/frameworkmock"
)

const (
	experimentalKey = "experimental"
	testOrgID       = "test-org"
	testScanID      = "test-scan"
	configFlag      = "config"
)

// MockRedTeamClient implements the RedTeamClient interface for testing.
type MockRedTeamClient struct {
	scanData           []redteamclient.AIScan
	scanResults        redteamclient.GetAIVulnerabilitiesResponseData
	createError        error
	getError           error
	listError          error
	resultsError       error
	checkEndpointError error
}

func (m *MockRedTeamClient) CheckAPIAvailability(_ context.Context, _ string) *errors.Error {
	if m.createError != nil {
		err := snyk_common_errors.NewServerError(m.createError.Error())
		return &err
	}
	return nil
}

func (m *MockRedTeamClient) RunScan(_ context.Context, _ string, _ *redteamclient.RedTeamConfig) (string, *errors.Error) {
	if m.createError != nil {
		err := snyk_common_errors.NewServerError(m.createError.Error())
		return "", &err
	}
	return "test-scan-id", nil
}

func (m *MockRedTeamClient) GetScan(_ context.Context, _, _ string) (*redteamclient.AIScan, *errors.Error) {
	if m.getError != nil {
		err := snyk_common_errors.NewServerError(m.getError.Error())
		return nil, &err
	}
	return &m.scanData[0], nil
}

func (m *MockRedTeamClient) GetScanResults(_ context.Context, _, _ string) (redteamclient.GetAIVulnerabilitiesResponseData, *errors.Error) {
	if m.resultsError != nil {
		err := snyk_common_errors.NewServerError(m.resultsError.Error())
		return redteamclient.GetAIVulnerabilitiesResponseData{}, &err
	}
	return m.scanResults, nil
}

func (m *MockRedTeamClient) ListScans(_ context.Context, _ string) ([]redteamclient.AIScan, *errors.Error) {
	if m.listError != nil {
		err := snyk_common_errors.NewServerError(m.listError.Error())
		return nil, &err
	}
	return m.scanData, nil
}

func (m *MockRedTeamClient) ValidateTarget(_ context.Context, _ string, _ *redteamclient.RedTeamConfig) *errors.Error {
	if m.checkEndpointError != nil {
		err := snyk_common_errors.NewServerError(m.checkEndpointError.Error())
		return &err
	}
	return nil
}

func TestRunRedTeamWorkflow_GetScanCommand(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set("organization", testOrgID)
	ictx.GetConfiguration().Set("scan-id", "test-scan-id")

	mockClient := &MockRedTeamClient{
		scanData: []redteamclient.AIScan{
			{
				ID:      uuid.New().String(),
				Status:  "completed",
				Created: &[]time.Time{time.Now()}[0],
			},
		},
	}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam", "get", "scan"}
	defer func() { os.Args = originalArgs }()

	results, err := redteam.RunRedTeamWorkflow(ictx, mockClient)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "text/plain", results[0].GetContentType())
}

func TestRunRedTeamWorkflow_CreateScanCommand(t *testing.T) {
	configContent := `
target:
  name: "Test Target"
  type: api
  context:
    purpose: "Testing chatbot"
  settings:
    url: "https://example.com"
    response_selector: "response"
    request_body_template: "{\"message\": \"{{prompt}}\"}"
`
	err := os.WriteFile("test-redteam.yaml", []byte(configContent), 0o600)
	require.NoError(t, err)
	defer os.Remove("test-redteam.yaml")

	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set("organization", testOrgID)
	ictx.GetConfiguration().Set("config", "test-redteam.yaml")

	mockClient := &MockRedTeamClient{
		scanResults: redteamclient.GetAIVulnerabilitiesResponseData{
			ID: uuid.New().String(),
			Results: []redteamclient.AIVulnerability{
				{
					ID:  "test-vid",
					URL: "test-url",
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
}

func TestRunRedTeamWorkflow_ExperimentalFlagRequired(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, false)

	mockClient := &MockRedTeamClient{}

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
	// Explicitly clear the organization to test the error case
	ictx.GetConfiguration().Set(configuration.ORGANIZATION, "")

	mockClient := &MockRedTeamClient{}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam"}
	defer func() { os.Args = originalArgs }()

	_, err := redteam.RunRedTeamWorkflow(ictx, mockClient)
	require.Error(t, err)
	// Just check that we get an error, the exact message might be wrapped
	assert.NotNil(t, err)
}

func TestHandleRunScanCommand_ConfigFileNotFound(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(configuration.ORGANIZATION, testOrgID)
	ictx.GetConfiguration().Set(configFlag, "nonexistent-config.yaml")

	mockClient := &MockRedTeamClient{}

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
  - invalid yaml syntax
`
	err := os.WriteFile("test-invalid.yaml", []byte(configContent), 0o600)
	require.NoError(t, err)
	defer os.Remove("test-invalid.yaml")

	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(configuration.ORGANIZATION, testOrgID)
	ictx.GetConfiguration().Set(configFlag, "test-invalid.yaml")

	mockClient := &MockRedTeamClient{}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam"}
	defer func() { os.Args = originalArgs }()

	_, err = redteam.RunRedTeamWorkflow(ictx, mockClient)
	require.Error(t, err)
}

func TestHandleRunScanCommand_ValidationFailure_MissingRequiredFields(t *testing.T) {
	configContent := `
target:
  name: "Test Target"
  type: api
`
	err := os.WriteFile("test-validation.yaml", []byte(configContent), 0o600)
	require.NoError(t, err)
	defer os.Remove("test-validation.yaml")

	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(configuration.ORGANIZATION, testOrgID)
	ictx.GetConfiguration().Set(configFlag, "test-validation.yaml")

	mockClient := &MockRedTeamClient{}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam"}
	defer func() { os.Args = originalArgs }()

	_, err = redteam.RunRedTeamWorkflow(ictx, mockClient)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validation")
}

func TestHandleRunScanCommand_ValidationFailure_InvalidTargetType(t *testing.T) {
	configContent := `
target:
  name: "Test Target"
  type: invalid_type
  settings:
    url: "https://example.com"
    response_selector: "response"
    request_body_template: "{\"message\": \"test\"}"
`
	err := os.WriteFile("test-invalid-type.yaml", []byte(configContent), 0o600)
	require.NoError(t, err)
	defer os.Remove("test-invalid-type.yaml")

	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(configuration.ORGANIZATION, testOrgID)
	ictx.GetConfiguration().Set(configFlag, "test-invalid-type.yaml")

	mockClient := &MockRedTeamClient{}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam"}
	defer func() { os.Args = originalArgs }()

	_, err = redteam.RunRedTeamWorkflow(ictx, mockClient)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validation")
}

func TestHandleRunScanCommand_ValidationFailure_InvalidURL(t *testing.T) {
	configContent := `
target:
  name: "Test Target"
  type: api
  settings:
    url: "not-a-valid-url"
    response_selector: "response"
    request_body_template: "{\"message\": \"test\"}"
`
	err := os.WriteFile("test-invalid-url.yaml", []byte(configContent), 0o600)
	require.NoError(t, err)
	defer os.Remove("test-invalid-url.yaml")

	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(configuration.ORGANIZATION, testOrgID)
	ictx.GetConfiguration().Set(configFlag, "test-invalid-url.yaml")

	mockClient := &MockRedTeamClient{}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam"}
	defer func() { os.Args = originalArgs }()

	_, err = redteam.RunRedTeamWorkflow(ictx, mockClient)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validation")
}

func TestHandleRunScanCommand_ValidationFailure_InvalidJSON(t *testing.T) {
	configContent := `
target:
  name: "Test Target"
  type: api
  settings:
    url: "https://example.com"
    response_selector: "response"
    request_body_template: "not valid json"
`
	err := os.WriteFile("test-invalid-json.yaml", []byte(configContent), 0o600)
	require.NoError(t, err)
	defer os.Remove("test-invalid-json.yaml")

	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(configuration.ORGANIZATION, testOrgID)
	ictx.GetConfiguration().Set(configFlag, "test-invalid-json.yaml")

	mockClient := &MockRedTeamClient{}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam"}
	defer func() { os.Args = originalArgs }()

	_, err = redteam.RunRedTeamWorkflow(ictx, mockClient)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validation")
}

func TestHandleRunScanCommand_ValidateTargetError(t *testing.T) {
	configContent := `
target:
  name: "Test Target"
  type: api
  settings:
    url: "https://example.com"
    response_selector: "response"
    request_body_template: "{\"message\": \"test\"}"
`
	err := os.WriteFile("test-validate-error.yaml", []byte(configContent), 0o600)
	require.NoError(t, err)
	defer os.Remove("test-validate-error.yaml")

	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(configuration.ORGANIZATION, testOrgID)
	ictx.GetConfiguration().Set(configFlag, "test-validate-error.yaml")

	mockClient := &MockRedTeamClient{
		checkEndpointError: assert.AnError,
	}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam"}
	defer func() { os.Args = originalArgs }()

	_, err = redteam.RunRedTeamWorkflow(ictx, mockClient)
	require.Error(t, err)
}
