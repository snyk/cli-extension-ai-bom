package redteamclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	errors "github.com/snyk/cli-extension-ai-bom/internal/errors"
)

func TestRedTeamClient_CreateScan(t *testing.T) {
	logger := zerolog.Nop()
	ui := ui.NewUserInterface()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/rest/orgs/test-org/ai-scans", r.URL.Path)
		assert.Equal(t, "application/vnd.api+json", r.Header.Get("Content-Type"))

		response := CreateScanResponseBody{
			Data: ScanData{
				Id:   "12345678-1234-1234-1234-123456789012",
				Type: "ai_scan",
				Attributes: ScanAttributes{
					Status:    "processing",
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				},
			},
		}

		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewRedTeamClient(&logger, &http.Client{}, ui, "test-agent", server.URL)

	config := RedTeamConfig{
		Options: RedTeamOptions{
			Target: TargetConfig{
				Name: "Test Target",
				URL:  "https://example.com",
			},
		},
	}

	scanID, err := client.CreateScan(context.Background(), "test-org", config)
	require.NoError(t, err)
	assert.Equal(t, "12345678-1234-1234-1234-123456789012", scanID)
}

func TestRedTeamClient_GetScan(t *testing.T) {
	logger := zerolog.Nop()
	ui := ui.NewUserInterface()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/rest/orgs/test-org/ai-scans/test-scan", r.URL.Path)

		response := ScanStatus{
			Id:   "test-scan",
			Type: "ai_scan",
			Attributes: ScanAttributes{
				Status:    "completed",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
		}

		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewRedTeamClient(&logger, &http.Client{}, ui, "test-agent", server.URL)

	scanStatus, err := client.GetScan(context.Background(), "test-org", "test-scan")
	require.NoError(t, err)
	assert.Equal(t, "completed", scanStatus.Status)
}

func TestRedTeamClient_GetScanResults(t *testing.T) {
	logger := zerolog.Nop()
	ui := ui.NewUserInterface()

	expectedResults := `{"findings": [{"severity": "high", "description": "Test finding"}]}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/rest/orgs/test-org/ai-scans/test-scan/results", r.URL.Path)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(expectedResults))
	}))
	defer server.Close()

	client := NewRedTeamClient(&logger, &http.Client{}, ui, "test-agent", server.URL)

	results, err := client.GetScanResults(context.Background(), "test-org", "test-scan")
	require.NoError(t, err)
	assert.Equal(t, expectedResults, results)
}

func TestRedTeamClient_ListScans(t *testing.T) {
	logger := zerolog.Nop()
	ui := ui.NewUserInterface()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/rest/orgs/test-org/ai-scans", r.URL.Path)

		response := ScanListResponse{
			Data: []ScanSummary{
				{
					Id:   "scan1",
					Type: "ai_scan",
					Attributes: ScanAttributes{
						Status:    "completed",
						CreatedAt: time.Now(),
						UpdatedAt: time.Now(),
					},
				},
				{
					Id:   "scan2",
					Type: "ai_scan",
					Attributes: ScanAttributes{
						Status:    "processing",
						CreatedAt: time.Now(),
						UpdatedAt: time.Now(),
					},
				},
			},
		}

		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewRedTeamClient(&logger, &http.Client{}, ui, "test-agent", server.URL)

	scans, err := client.ListScans(context.Background(), "test-org")
	require.NoError(t, err)
	assert.Len(t, scans, 2)
	assert.Equal(t, "scan1", scans[0].Id)
	assert.Equal(t, "completed", scans[0].Attributes.Status)
}

func TestRedTeamClient_ErrorHandling(t *testing.T) {
	logger := zerolog.Nop()
	ui := ui.NewUserInterface()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "unauthorized"}`))
	}))
	defer server.Close()

	client := NewRedTeamClient(&logger, &http.Client{}, ui, "test-agent", server.URL)

	_, err := client.GetScan(context.Background(), "test-org", "test-scan")
	require.Error(t, err)
	assert.IsType(t, &errors.AiBomError{}, err)
}
