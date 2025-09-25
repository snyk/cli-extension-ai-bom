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

	"github.com/snyk/cli-extension-ai-bom/internal/commands/redteam"
	redteamclient "github.com/snyk/cli-extension-ai-bom/internal/services/red-team-client"
	"github.com/snyk/cli-extension-ai-bom/mocks/frameworkmock"
)

const (
	experimentalKey = "experimental"
	testOrgID       = "test-org"
	testScanID      = "test-scan"
)

// MockRedTeamClient implements the RedTeamClient interface for testing.
type MockRedTeamClient struct {
	scans              []redteamclient.ScanSummary
	scanStatus         *redteamclient.ScanStatus
	scanResults        string
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

func (m *MockRedTeamClient) CreateScan(_ context.Context, _ string, _ *redteamclient.RedTeamConfig) (string, *errors.Error) {
	if m.createError != nil {
		err := snyk_common_errors.NewServerError(m.createError.Error())
		return "", &err
	}
	return "test-scan-id", nil
}

func (m *MockRedTeamClient) GetScan(_ context.Context, _, _ string) (*redteamclient.ScanStatus, *errors.Error) {
	if m.getError != nil {
		err := snyk_common_errors.NewServerError(m.getError.Error())
		return nil, &err
	}
	return m.scanStatus, nil
}

func (m *MockRedTeamClient) GetScanResults(_ context.Context, _, _ string) (string, *errors.Error) {
	if m.resultsError != nil {
		err := snyk_common_errors.NewServerError(m.resultsError.Error())
		return "", &err
	}
	return m.scanResults, nil
}

func (m *MockRedTeamClient) ListScans(_ context.Context, _ string) ([]redteamclient.ScanSummary, *errors.Error) {
	if m.listError != nil {
		err := snyk_common_errors.NewServerError(m.listError.Error())
		return nil, &err
	}
	return m.scans, nil
}

func (m *MockRedTeamClient) CheckEndpointAvailability(_ context.Context, _ string, _ *redteamclient.RedTeamConfig) *errors.Error {
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
		scanStatus: &redteamclient.ScanStatus{
			ID:   uuid.New(),
			Type: "ai_scan",
			Attributes: redteamclient.ScanAttributes{
				Status:    "completed",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
		},
		scanResults: `{"findings": [{"severity": "high", "description": "Test finding"}]}`,
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
	// Create a test config file
	configContent := `
options:
  target:
    name: "Test Target"
    url: "https://example.com"
    method: "POST"
    headers:
      Content-Type: "application/json"
`
	err := os.WriteFile("test-redteam.yaml", []byte(configContent), 0o600)
	require.NoError(t, err)
	defer os.Remove("test-redteam.yaml")

	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set("organization", testOrgID)
	ictx.GetConfiguration().Set("config", "test-redteam.yaml")

	mockClient := &MockRedTeamClient{
		scanResults: `{"findings": [{"severity": "high", "description": "Test finding"}]}`,
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
	// Don't set organization, leave it empty

	mockClient := &MockRedTeamClient{}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam"}
	defer func() { os.Args = originalArgs }()

	_, err := redteam.RunRedTeamWorkflow(ictx, mockClient)
	require.Error(t, err)
	// Just check that we get an error, the exact message might be wrapped
	assert.NotNil(t, err)
}
