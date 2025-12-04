package redteamclientmock

import (
	"context"

	redteamclient "github.com/snyk/cli-extension-ai-bom/internal/services/red-team-client"

	redteam_errors "github.com/snyk/cli-extension-ai-bom/internal/errors/redteam"
)

// MockRedTeamClient implements the RedTeamClient interface for testing.
type MockRedTeamClient struct {
	ScanData      []redteamclient.AIScan
	ScanResults   redteamclient.GetAIVulnerabilitiesResponseData
	CreateError   *redteam_errors.RedTeamError
	GetError      *redteam_errors.RedTeamError
	ResultsError  *redteam_errors.RedTeamError
	GenerateError *redteam_errors.RedTeamError
	ListError     *redteam_errors.RedTeamError
	DeleteError   *redteam_errors.RedTeamError
	GetScanCalls  int
	PollingScans  []redteamclient.AIScan
}

var _ redteamclient.RedTeamClient = (*MockRedTeamClient)(nil)

func (m *MockRedTeamClient) CreateScan(_ context.Context, _ string, _ *redteamclient.RedTeamConfig) (string, *redteam_errors.RedTeamError) {
	if m.CreateError != nil {
		return "", m.CreateError
	}
	return "test-scan-id", nil
}

func (m *MockRedTeamClient) GetScan(_ context.Context, _, _ string) (*redteamclient.AIScan, *redteam_errors.RedTeamError) {
	if m.GetError != nil {
		return nil, m.GetError
	}

	if len(m.PollingScans) > 0 {
		if m.GetScanCalls < len(m.PollingScans) {
			scan := m.PollingScans[m.GetScanCalls]
			m.GetScanCalls++
			return &scan, nil
		}
		return &m.PollingScans[len(m.PollingScans)-1], nil
	}

	if len(m.ScanData) > 0 {
		return &m.ScanData[0], nil
	}

	return &redteamclient.AIScan{
		ID:     "test-scan-id",
		Status: redteamclient.AIScanStatusCompleted,
	}, nil
}

func (m *MockRedTeamClient) GetScanResults(_ context.Context, _, _ string) (redteamclient.GetAIVulnerabilitiesResponseData, *redteam_errors.RedTeamError) {
	if m.ResultsError != nil {
		return redteamclient.GetAIVulnerabilitiesResponseData{}, m.ResultsError
	}
	return m.ScanResults, nil
}

func (m *MockRedTeamClient) CreateScanningAgent(_ context.Context, _, _ string) (*redteamclient.AIScanningAgent, *redteam_errors.RedTeamError) {
	if m.CreateError != nil {
		return nil, m.CreateError
	}
	return &redteamclient.AIScanningAgent{
		ID:   "test-scanning-agent-id",
		Name: "test-scanning-agent-name",
	}, nil
}

func (m *MockRedTeamClient) GenerateScanningAgentConfig(
	_ context.Context, _, _ string,
) (*redteamclient.GenerateAIScanningAgentConfigData, *redteam_errors.RedTeamError) {
	if m.GenerateError != nil {
		return nil, m.GenerateError
	}
	return &redteamclient.GenerateAIScanningAgentConfigData{
		FarcasterAgentToken: "test-farcaster-agent-token",
		FarcasterAPIURL:     "test-farcaster-api-url",
	}, nil
}

func (m *MockRedTeamClient) ListScanningAgents(_ context.Context, _ string) ([]redteamclient.AIScanningAgent, *redteam_errors.RedTeamError) {
	if m.ListError != nil {
		return nil, m.ListError
	}
	return []redteamclient.AIScanningAgent{
		{
			ID:   "test-scanning-agent-id",
			Name: "test-scanning-agent-name",
		},
	}, nil
}

func (m *MockRedTeamClient) DeleteScanningAgent(_ context.Context, _, _ string) *redteam_errors.RedTeamError {
	if m.DeleteError != nil {
		return m.DeleteError
	}
	return nil
}
