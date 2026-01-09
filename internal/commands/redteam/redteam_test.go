package redteam_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/cli-extension-ai-bom/internal/commands/redteam"
	"github.com/snyk/cli-extension-ai-bom/internal/commands/redteam/tui"
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

func init() {
	tui.PollInterval = 100 * time.Millisecond
}

var testTUIOpts = []tea.ProgramOption{
	tea.WithInput(bytes.NewBuffer(nil)), // Default to no input
	tea.WithOutput(io.Discard),
}

func driveTUI(t *testing.T, w *os.File) {
	t.Helper()
	// Simple driver: Enter, Enter, Wait, Quit
	go func() {
		defer w.Close()
		time.Sleep(100 * time.Millisecond)
		w.WriteString("\r") // Welcome -> ConfigConfirmation
		t.Log("Sent Enter (Welcome)")
		time.Sleep(100 * time.Millisecond)
		w.WriteString("\r") // ConfigConfirmation -> Scanning
		t.Log("Sent Enter (ConfigConfirmation)")

		// Wait for scan to complete (poll interval 2s)
		time.Sleep(1 * time.Second)

		w.WriteString("q") // Results -> Quit
		t.Log("Sent q (Quit)")
	}()
}

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

	r, w, _ := os.Pipe()
	driveTUI(t, w)
	opts := append([]tea.ProgramOption(nil), testTUIOpts...)
	opts = append(opts, tea.WithInput(r))

	results, err := redteam.RunRedTeamWorkflow(ictx, mockClient, ictx.GetEnhancedLogger(), opts...)
	require.NoError(t, err)
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

	_, err := redteam.RunRedTeamWorkflow(ictx, mockClient, ictx.GetEnhancedLogger(), testTUIOpts...)
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

	// Inject 'q' to quit TUI if it starts
	inputReader, inputWriter, _ := os.Pipe()
	go func() {
		defer inputWriter.Close()
		time.Sleep(50 * time.Millisecond)
		inputWriter.WriteString("q")
	}()
	opts := append([]tea.ProgramOption(nil), testTUIOpts...)
	opts = append(opts, tea.WithInput(inputReader))

	_, err := redteam.RunRedTeamWorkflow(ictx, mockClient, ictx.GetEnhancedLogger(), opts...)
	require.NoError(t, err)
}

func testWorkflowWithConfigPath(t *testing.T, configPath string) {
	t.Helper()
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set(organizationKey, testOrgID)
	ictx.GetConfiguration().Set(configFlag, configPath)

	mockClient := &redteamclientmock.MockRedTeamClient{
		PollingScans: []redteamclient.AIScan{
			{ID: "test-scan-id", Status: redteamclient.AIScanStatusCompleted},
		},
	}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam"}
	defer func() { os.Args = originalArgs }()

	inputReader, inputWriter, _ := os.Pipe()
	go func() {
		defer inputWriter.Close()
		time.Sleep(50 * time.Millisecond)
		inputWriter.WriteString("q")
	}()
	opts := append([]tea.ProgramOption(nil), testTUIOpts...)
	opts = append(opts, tea.WithInput(inputReader))

	results, err := redteam.RunRedTeamWorkflow(ictx, mockClient, ictx.GetEnhancedLogger(), opts...)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestHandleRunScanCommand_ConfigFileNotFound(t *testing.T) {
	testWorkflowWithConfigPath(t, "nonexistent-config.yaml")
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

			r, w, _ := os.Pipe()
			go func() {
				defer w.Close()
				time.Sleep(50 * time.Millisecond)
				w.WriteString("q")
			}()
			opts := append([]tea.ProgramOption(nil), testTUIOpts...)
			opts = append(opts, tea.WithInput(r))

			_, err = redteam.RunRedTeamWorkflow(ictx, mockClient, ictx.GetEnhancedLogger(), opts...)
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

	r, w, _ := os.Pipe()
	go func() {
		defer w.Close()
		time.Sleep(100 * time.Millisecond)
		w.WriteString("\r") // Welcome -> ConfigConfirmation
		time.Sleep(100 * time.Millisecond)
		w.WriteString("\r") // ConfigConfirmation -> Scanning (fails) -> Error
		time.Sleep(100 * time.Millisecond)
		w.Write([]byte{3}) // Error -> Quit (Ctrl+C)
	}()
	opts := append([]tea.ProgramOption(nil), testTUIOpts...)
	opts = append(opts, tea.WithInput(r))

	_, err := redteam.RunRedTeamWorkflow(ictx, mockClient, ictx.GetEnhancedLogger(), opts...)
	require.Error(t, err)
}

func TestHandleRunScanCommand_CustomConfigPathDoesNotExist(t *testing.T) {
	testWorkflowWithConfigPath(t, "path-that-does-not-exist/test-custom-config.yaml")
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

	r, w, _ := os.Pipe()
	driveTUI(t, w)
	opts := append([]tea.ProgramOption(nil), testTUIOpts...)
	opts = append(opts, tea.WithInput(r))

	_, err := redteam.RunRedTeamWorkflow(ictx, mockClient, ictx.GetEnhancedLogger(), opts...)
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
			expectedErrorText:  []string{"Scan failed: scan_error - Scan failed due to internal error"},
			expectedUnwrapText: "Scan failed: scan_error - Scan failed due to internal error",
		},
		{
			name:               "network error",
			errorCode:          "network_error",
			errorMessage:       "Connection timeout",
			expectedErrorText:  []string{"Scan failed: network_error - Connection timeout"},
			expectedUnwrapText: "Scan failed: network_error - Connection timeout",
		},
		{
			name:               "context error",
			errorCode:          "context_error",
			errorMessage:       "Invalid context",
			expectedErrorText:  []string{"Scan failed: context_error - Invalid context"},
			expectedUnwrapText: "Scan failed: context_error - Invalid context",
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

			r, w, _ := os.Pipe()
			go func() {
				defer w.Close()
				time.Sleep(100 * time.Millisecond)
				w.WriteString("\r") // Welcome -> ConfigConfirmation
				time.Sleep(100 * time.Millisecond)
				w.WriteString("\r") // ConfigConfirmation -> Scanning -> Polling -> Failed -> Error
				time.Sleep(1 * time.Second)
				w.Write([]byte{3}) // Error -> Quit (Ctrl+C)
			}()
			opts := append([]tea.ProgramOption(nil), testTUIOpts...)
			opts = append(opts, tea.WithInput(r))

			_, err := redteam.RunRedTeamWorkflow(ictx, mockClient, ictx.GetEnhancedLogger(), opts...)
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

	r, w, _ := os.Pipe()
	driveTUI(t, w)
	opts := append([]tea.ProgramOption(nil), testTUIOpts...)
	opts = append(opts, tea.WithInput(r))

	_, err := redteam.RunRedTeamWorkflow(ictx, mockClient, ictx.GetEnhancedLogger(), opts...)
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

	_, err := redteam.RunRedTeamWorkflow(ictx, mockClient, ictx.GetEnhancedLogger(), testTUIOpts...)
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

	r, w, _ := os.Pipe()
	driveTUI(t, w)
	opts := append([]tea.ProgramOption(nil), testTUIOpts...)
	opts = append(opts, tea.WithInput(r))

	_, err := redteam.RunRedTeamWorkflow(ictx, mockClient, ictx.GetEnhancedLogger(), opts...)
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

	_, err := redteam.RunRedTeamWorkflow(ictx, mockClient, ictx.GetEnhancedLogger(), testTUIOpts...)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Scanning agent ID is not a valid UUID")
}
