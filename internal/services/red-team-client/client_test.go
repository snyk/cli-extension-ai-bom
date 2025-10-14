package redteamclient_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	snyk_errors "github.com/snyk/error-catalog-golang-public/snyk_errors"

	redteamclient "github.com/snyk/cli-extension-ai-bom/internal/services/red-team-client"
	"github.com/snyk/cli-extension-ai-bom/mocks/redteamclientmock"
)

const (
	testOrgID  = "test-org"
	testScanID = "test-scan"
)

func TestRedTeamClient_CreateScan(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := redteamclientmock.NewMockRedTeamClient(ctrl)

	expectedScanID := "12345678-1234-1234-1234-123456789012"

	mockClient.EXPECT().
		RunScan(gomock.Any(), testOrgID, gomock.Any()).
		Return(expectedScanID, (*snyk_errors.Error)(nil)).
		Times(1)

	scanID, err := mockClient.RunScan(context.Background(), testOrgID, &redteamclient.RedTeamConfig{})
	assert.Nil(t, err)
	assert.Equal(t, expectedScanID, scanID)
}

func TestRedTeamClient_GetScan(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := redteamclientmock.NewMockRedTeamClient(ctrl)

	expectedScanStatus := &redteamclient.AIScan{
		ID:      "12345678-1234-1234-1234-123456789012",
		Status:  redteamclient.ScanStatusCompleted,
		Created: func() *time.Time { t := time.Now(); return &t }(),
	}

	mockClient.EXPECT().
		GetScan(gomock.Any(), testOrgID, testScanID).
		Return(expectedScanStatus, nil).
		Times(1)

	scanData, err := mockClient.GetScan(context.Background(), testOrgID, testScanID)
	if err != nil {
		t.Fatalf("GetScan returned error: %v", err)
	}
	assert.Equal(t, redteamclient.ScanStatusCompleted, scanData.Status)
}

func TestRedTeamClient_GetScanResults(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := redteamclientmock.NewMockRedTeamClient(ctrl)

	expectedResults := redteamclient.GetAIVulnerabilitiesResponseData{
		ID: "test-scan",
		Results: []redteamclient.AIVulnerability{
			{
				ID:       "vuln1",
				Severity: "high",
				URL:      "https://example.com",
			},
		},
	}

	mockClient.EXPECT().
		GetScanResults(gomock.Any(), testOrgID, testScanID).
		Return(expectedResults, nil).
		Times(1)

	results, err := mockClient.GetScanResults(context.Background(), testOrgID, testScanID)
	if err != nil {
		t.Fatalf("GetScanResults returned error: %v", err)
	}
	assert.Equal(t, expectedResults, results)
}

func TestRedTeamClient_ListScans(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := redteamclientmock.NewMockRedTeamClient(ctrl)

	expectedScans := []redteamclient.AIScan{
		{
			ID:      "scan1",
			Status:  redteamclient.ScanStatusCompleted,
			Created: func() *time.Time { t := time.Now(); return &t }(),
		},
		{
			ID:      "scan2",
			Status:  redteamclient.ScanStatusStarted,
			Created: func() *time.Time { t := time.Now(); return &t }(),
		},
	}

	mockClient.EXPECT().
		ListScans(gomock.Any(), testOrgID).
		Return(expectedScans, nil).
		Times(1)

	scans, err := mockClient.ListScans(context.Background(), testOrgID)
	if err != nil {
		t.Fatalf("ListScans returned error: %v", err)
	}
	assert.Len(t, scans, 2)
	assert.Equal(t, "scan1", scans[0].ID)
	assert.Equal(t, redteamclient.ScanStatusCompleted, scans[0].Status)
}

func TestRedTeamClient_ErrorHandling(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := redteamclientmock.NewMockRedTeamClient(ctrl)

	expectedError := &snyk_errors.Error{}

	mockClient.EXPECT().
		GetScan(gomock.Any(), testOrgID, testScanID).
		Return(nil, expectedError).
		Times(1)

	_, err := mockClient.GetScan(context.Background(), testOrgID, testScanID)
	require.Error(t, err)
	assert.Equal(t, expectedError, err)
}
