package redteam

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-ai-bom/internal/errors"
	redteamclient "github.com/snyk/cli-extension-ai-bom/internal/services/red-team-client"
	"github.com/snyk/cli-extension-ai-bom/mocks/frameworkmock"
)

// MockRedTeamClient implements the RedTeamClient interface for testing
type MockRedTeamClient struct {
	scans        []redteamclient.ScanSummary
	scanStatus   *redteamclient.ScanStatus
	scanResults  string
	createError  error
	getError     error
	listError    error
	resultsError error
}

func (m *MockRedTeamClient) CheckAPIAvailability(ctx context.Context, orgID string) *errors.AiBomError {
	if m.createError != nil {
		return errors.NewInternalError(m.createError.Error())
	}
	return nil
}

func (m *MockRedTeamClient) CreateScan(ctx context.Context, orgID string, config redteamclient.RedTeamConfig) (string, *errors.AiBomError) {
	if m.createError != nil {
		return "", errors.NewInternalError(m.createError.Error())
	}
	return "test-scan-id", nil
}

func (m *MockRedTeamClient) GetScan(ctx context.Context, orgID, scanID string) (*redteamclient.ScanStatus, *errors.AiBomError) {
	if m.getError != nil {
		return nil, errors.NewInternalError(m.getError.Error())
	}
	return m.scanStatus, nil
}

func (m *MockRedTeamClient) GetScanResults(ctx context.Context, orgID, scanID string) (string, *errors.AiBomError) {
	if m.resultsError != nil {
		return "", errors.NewInternalError(m.resultsError.Error())
	}
	return m.scanResults, nil
}

func (m *MockRedTeamClient) ListScans(ctx context.Context, orgID string) ([]redteamclient.ScanSummary, *errors.AiBomError) {
	if m.listError != nil {
		return nil, errors.NewInternalError(m.listError.Error())
	}
	return m.scans, nil
}

func TestRunRedTeamWorkflow_InitCommand(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set("experimental", true)
	ictx.GetConfiguration().Set("name", "Test Target")
	ictx.GetConfiguration().Set("url", "https://example.com")
	ictx.GetConfiguration().Set("config", "test-redteam.yaml")

	mockClient := &MockRedTeamClient{}

	// Test init command
	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam", "init"}
	defer func() { os.Args = originalArgs }()

	_, err := RunRedTeamWorkflow(ictx, mockClient)
	require.NoError(t, err)

	// Check if config file was created
	configData, err := os.ReadFile("test-redteam.yaml")
	require.NoError(t, err)
	assert.Contains(t, string(configData), "Test Target")
	assert.Contains(t, string(configData), "https://example.com")

	// Clean up
	os.Remove("test-redteam.yaml")
}

func TestRunRedTeamWorkflow_ListScansCommand(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set("experimental", true)
	ictx.GetConfiguration().Set("organization", "test-org")

	mockClient := &MockRedTeamClient{
		scans: []redteamclient.ScanSummary{
			{
				Id:   uuid.New(),
				Type: "ai_scan",
				Attributes: redteamclient.ScanAttributes{
					Status:    "completed",
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				},
			},
		},
	}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam", "get", "scans"}
	defer func() { os.Args = originalArgs }()

	results, err := RunRedTeamWorkflow(ictx, mockClient)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "text/plain", results[0].GetContentType())
}

func TestRunRedTeamWorkflow_GetScanCommand(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set("experimental", true)
	ictx.GetConfiguration().Set("organization", "test-org")
	ictx.GetConfiguration().Set("scan-id", "test-scan-id")

	mockClient := &MockRedTeamClient{
		scanStatus: &redteamclient.ScanStatus{
			Id:   uuid.New(),
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

	results, err := RunRedTeamWorkflow(ictx, mockClient)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "text/plain", results[0].GetContentType())
}

func TestRunRedTeamWorkflow_RunScanCommand(t *testing.T) {
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
	err := os.WriteFile("test-redteam.yaml", []byte(configContent), 0644)
	require.NoError(t, err)
	defer os.Remove("test-redteam.yaml")

	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set("experimental", true)
	ictx.GetConfiguration().Set("organization", "test-org")
	ictx.GetConfiguration().Set("config", "test-redteam.yaml")

	mockClient := &MockRedTeamClient{
		scanResults: `{"findings": [{"severity": "high", "description": "Test finding"}]}`,
	}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam"}
	defer func() { os.Args = originalArgs }()

	results, err := RunRedTeamWorkflow(ictx, mockClient)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "application/json", results[0].GetContentType())
}

func TestRunRedTeamWorkflow_ExperimentalFlagRequired(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set("experimental", false)

	mockClient := &MockRedTeamClient{}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam"}
	defer func() { os.Args = originalArgs }()

	_, err := RunRedTeamWorkflow(ictx, mockClient)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "experimental")
}

func TestRunRedTeamWorkflow_NoOrgID(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set("experimental", true)
	// Don't set organization, leave it empty

	mockClient := &MockRedTeamClient{}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam"}
	defer func() { os.Args = originalArgs }()

	_, err := RunRedTeamWorkflow(ictx, mockClient)
	require.Error(t, err)
	// Just check that we get an error, the exact message might be wrapped
	assert.NotNil(t, err)
}
