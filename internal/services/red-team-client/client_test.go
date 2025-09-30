package redteamclient_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
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
		RunScan(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(expectedScanID, nil).
		AnyTimes()

	scanID, err := mockClient.RunScan(context.Background(), testOrgID, &redteamclient.RedTeamConfig{})
	require.NoError(t, err)
	assert.Equal(t, expectedScanID, scanID)
}

func TestRedTeamClient_GetScan(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := redteamclientmock.NewMockRedTeamClient(ctrl)

	expectedScanStatus := &redteamclient.ScanStatus{
		ID:   uuid.MustParse("12345678-1234-1234-1234-123456789012"),
		Type: "ai_scan",
		Attributes: redteamclient.ScanAttributes{
			Status:    "completed",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	mockClient.EXPECT().
		GetScan(gomock.Any(), testOrgID, testScanID).
		Return(expectedScanStatus, nil).
		Times(1)

	scanStatus, err := mockClient.GetScan(context.Background(), testOrgID, testScanID)
	require.NoError(t, err)
	assert.Equal(t, "completed", scanStatus.Attributes.Status)
}

func TestRedTeamClient_GetScanResults(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := redteamclientmock.NewMockRedTeamClient(ctrl)

	expectedResults := `{"findings": [{"severity": "high", "description": "Test finding"}]}`

	mockClient.EXPECT().
		GetScanResults(gomock.Any(), testOrgID, testScanID).
		Return(expectedResults, nil).
		Times(1)

	results, err := mockClient.GetScanResults(context.Background(), testOrgID, testScanID)
	require.NoError(t, err)
	assert.Equal(t, expectedResults, results)
}

func TestRedTeamClient_ListScans(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := redteamclientmock.NewMockRedTeamClient(ctrl)

	expectedScans := []redteamclient.ScanSummary{
		{
			ID:   uuid.MustParse("scan1"),
			Type: "ai_scan",
			Attributes: redteamclient.ScanAttributes{
				Status:    "completed",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
		},
		{
			ID:   uuid.MustParse("scan2"),
			Type: "ai_scan",
			Attributes: redteamclient.ScanAttributes{
				Status:    "processing",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
		},
	}

	mockClient.EXPECT().
		ListScans(gomock.Any(), testOrgID).
		Return(expectedScans, nil).
		Times(1)

	scans, err := mockClient.ListScans(context.Background(), testOrgID)
	require.NoError(t, err)
	assert.Len(t, scans, 2)
	assert.Equal(t, "scan1", scans[0].ID.String())
	assert.Equal(t, "completed", scans[0].Attributes.Status)
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
