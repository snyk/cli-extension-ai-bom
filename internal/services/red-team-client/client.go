package redteamclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/ui"

	snyk_common_errors "github.com/snyk/error-catalog-golang-public/snyk"
	errors "github.com/snyk/error-catalog-golang-public/snyk_errors"
)

type RedTeamClient interface {
	CheckAPIAvailability(ctx context.Context, orgID string) *errors.Error
	CheckEndpointAvailability(ctx context.Context, orgID string, config *RedTeamConfig) *errors.Error
	CreateScan(ctx context.Context, orgID string, config *RedTeamConfig) (string, *errors.Error)
	GetScan(ctx context.Context, orgID, scanID string) (*ScanStatus, *errors.Error)
	GetScanResults(ctx context.Context, orgID, scanID string) (string, *errors.Error)
	ListScans(ctx context.Context, orgID string) ([]ScanSummary, *errors.Error)
}

type ClientImpl struct {
	userAgent     string
	baseURL       string
	httpClient    *http.Client
	logger        *zerolog.Logger
	userInterface ui.UserInterface
}

var _ RedTeamClient = (*ClientImpl)(nil) // Assert that ClientImpl implements RedTeamClient

const (
	maxPollAttempts      = 7200
	pollInterval         = 500 * time.Millisecond
	failedProgressBarMsg = "Failed to update progress bar"
)

func NewRedTeamClient(
	logger *zerolog.Logger,
	httpClient *http.Client,
	userInterface ui.UserInterface,
	userAgent string,
	baseURL string,
) *ClientImpl {
	httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		// Return http.ErrUseLastResponse to not follow redirects
		return http.ErrUseLastResponse
	}
	return &ClientImpl{
		userAgent:     userAgent,
		baseURL:       baseURL,
		httpClient:    httpClient,
		logger:        logger,
		userInterface: userInterface,
	}
}

var APIVersion = "2024-10-15"

func (c *ClientImpl) CheckAPIAvailability(_ context.Context, _ string) *errors.Error {
	// TODO(pkey): implement this checking logic later

	return nil
}

func (c *ClientImpl) CheckEndpointAvailability(_ context.Context, _ string, _ *RedTeamConfig) *errors.Error {
	progressBar := c.userInterface.NewProgressBar()
	progressBar.SetTitle("Verifying endpoint is available...")
	progressErr := progressBar.UpdateProgress(ui.InfiniteProgress)
	if progressErr != nil {
		c.logger.Debug().Err(progressErr).Msg(failedProgressBarMsg)
	}
	defer func() {
		progressErr = progressBar.Clear()
		if progressErr != nil {
			c.logger.Debug().Err(progressErr).Msg("Failed to clear progress bar")
		}
	}()

	time.Sleep(1 * time.Second)
	return nil
}

func (c *ClientImpl) CreateScan(ctx context.Context, orgID string, config *RedTeamConfig) (string, *errors.Error) {
	// Setup progress bar

	progressBar := c.userInterface.NewProgressBar()
	progressBar.SetTitle("Creating a scan...")
	progressErr := progressBar.UpdateProgress(ui.InfiniteProgress)

	if progressErr != nil {
		c.logger.Debug().Err(progressErr).Msg(failedProgressBarMsg)
	}
	defer func() {
		progressErr = progressBar.Clear()
		if progressErr != nil {
			c.logger.Debug().Err(progressErr).Msg("Failed to clear progress bar")
		}
	}()

	time.Sleep(2 * time.Second)
	scanID := c.createScan(ctx, orgID, config)

	scanStatus, err := c.pollForScanComplete(ctx, orgID, scanID)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while polling for the scan")
		return "", err
	}

	if scanStatus.Attributes.Status != "completed" {
		err := snyk_common_errors.NewServerError("Red team scan did not complete successfully")
		return "", &err
	}

	progressBar.SetTitle("Scan completed")
	if err := progressBar.UpdateProgress(1.0); err != nil {
		c.logger.Debug().Err(err).Msg("Failed to update progress bar")
	}

	return scanID, nil
}

func (c *ClientImpl) GetScan(_ context.Context, _, scanID string) (*ScanStatus, *errors.Error) {
	// Mock implementation - service doesn't exist yet
	c.logger.Debug().Str("scanId", scanID).Msg("returning mock scan status")

	// Parse scanID as UUID
	scanUUID, err := uuid.Parse(scanID)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while parsing scanID as UUID")
		err := snyk_common_errors.NewServerError(fmt.Sprintf("Invalid scan ID format: %s", err.Error()))
		return nil, &err
	}

	// Return a mock completed scan status
	mockScanStatus := &ScanStatus{
		ID:   scanUUID,
		Type: "ai-scan",
		Attributes: ScanAttributes{
			Status:    "completed",
			CreatedAt: time.Now().Add(-5 * time.Minute),
			UpdatedAt: time.Now(),
			Config: RedTeamConfig{
				Options: RedTeamOptions{
					Target: TargetConfig{
						Name: "Mock Target",
						URL:  "https://example.com",
					},
				},
				Attacks: []string{"mock-attack"},
			},
		},
	}

	return mockScanStatus, nil
}

func (c *ClientImpl) GetScanResults(_ context.Context, _, scanID string) (string, *errors.Error) {
	progressBar := c.userInterface.NewProgressBar()
	progressBar.SetTitle("Getting scan results...")
	progressErr := progressBar.UpdateProgress(ui.InfiniteProgress)

	if progressErr != nil {
		c.logger.Debug().Err(progressErr).Msg(failedProgressBarMsg)
	}
	defer func() {
		progressErr = progressBar.Clear()
		if progressErr != nil {
			c.logger.Debug().Err(progressErr).Msg("Failed to clear progress bar")
		}
	}()

	time.Sleep(2 * time.Second)
	// Mock implementation - service doesn't exist yet
	c.logger.Debug().Str("scanId", scanID).Msg("returning mock scan results")

	// Read mock JSON from file
	mockJSONBytes, err := os.ReadFile("mock.json")
	if err != nil {
		c.logger.Debug().Err(err).Msg("error reading mock.json file")
		serverErr := snyk_common_errors.NewServerError("Error reading mock data file")
		return "", &serverErr
	}

	// Replace placeholder with actual scan ID
	mockResults := strings.ReplaceAll(string(mockJSONBytes), "SCAN_ID_PLACEHOLDER", scanID)

	// Compact the JSON by removing whitespace and newlines
	var compactJSON interface{}
	if unmarshalErr := json.Unmarshal([]byte(mockResults), &compactJSON); unmarshalErr != nil {
		c.logger.Debug().Err(unmarshalErr).Msg("error unmarshaling mock JSON")
		serverErr := snyk_common_errors.NewServerError("Error processing mock data")
		return "", &serverErr
	}

	compactBytes, marshalErr := json.Marshal(compactJSON)
	if marshalErr != nil {
		c.logger.Debug().Err(marshalErr).Msg("error marshaling compact JSON")
		serverErr := snyk_common_errors.NewServerError("Error compacting mock data")
		return "", &serverErr
	}

	mockResults = string(compactBytes)

	progressBar.SetTitle("Scan results retrieved")
	if err := progressBar.UpdateProgress(1.0); err != nil {
		c.logger.Debug().Err(err).Msg("Failed to update progress bar")
	}

	return mockResults, nil
}

func (c *ClientImpl) ListScans(ctx context.Context, orgID string) ([]ScanSummary, *errors.Error) {
	url := fmt.Sprintf("%s/rest/orgs/%s/ai-scans?version=%s", c.baseURL, orgID, APIVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while building ListScans request")
		err := snyk_common_errors.NewServerError(fmt.Sprintf("Error building ListScans request: %s", err.Error()))
		return nil, &err
	}
	c.setCommonHeaders(url, req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, c.redTeamErrorFromHTTPClientError("ListScans", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while reading ListScans response body")
		err := snyk_common_errors.NewServerError(fmt.Sprintf("Failed to read ListScans response body: %s", err.Error()))
		return nil, &err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, c.redTeamErrorFromHTTPStatusCode("ListScans", resp.StatusCode, bodyBytes)
	}

	var scanList ScanListResponse
	err = json.Unmarshal(bodyBytes, &scanList)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while unmarshaling ScanListResponse")
		err := snyk_common_errors.NewServerError(fmt.Sprintf("Failed to unmarshal ScanListResponse: %s", err.Error()))
		return nil, &err
	}

	return scanList.Data, nil
}

func (c *ClientImpl) redTeamErrorFromHTTPClientError(endPoint string, err error) *errors.Error {
	c.logger.Debug().Err(err).Msg(fmt.Sprintf("%s request HTTP error", endPoint))
	if strings.Contains(strings.ToLower(err.Error()), "authentication") {
		authErr := snyk_common_errors.NewUnauthorisedError(fmt.Sprintf("%s request failed with authentication error.", endPoint))
		return &authErr
	}
	if strings.Contains(strings.ToLower(err.Error()), "forbidden") {
		forbiddenErr := snyk_common_errors.NewUnauthorisedError(fmt.Sprintf("%s request failed with forbidden error.", endPoint))
		return &forbiddenErr
	}
	serverErr := snyk_common_errors.NewServerError(fmt.Sprintf("%s request HTTP error: %s", endPoint, err.Error()))
	return &serverErr
}

func (c *ClientImpl) redTeamErrorFromHTTPStatusCode(endPoint string, statusCode int, bodyBytes []byte) *errors.Error {
	errMsg := fmt.Sprintf(
		"unexpected status code %d for %s", statusCode, endPoint)
	c.logger.Debug().Str("responseBody", string(bodyBytes)).Msg(errMsg)
	switch statusCode {
	case http.StatusUnauthorized:
		authErr := snyk_common_errors.NewUnauthorisedError(errMsg)
		return &authErr
	case http.StatusForbidden:
		forbiddenErr := snyk_common_errors.NewUnauthorisedError(errMsg)
		return &forbiddenErr
	default:
		serverErr := snyk_common_errors.NewServerError(errMsg)
		return &serverErr
	}
}

func (c *ClientImpl) createScan(
	_ context.Context,
	_ string,
	_ *RedTeamConfig,
) string {
	// Mock implementation - service doesn't exist yet
	c.logger.Debug().Msg("creating mock red team scan")

	// Generate a new UUID for the mock scan
	scanID := uuid.New().String()
	c.logger.Debug().Str("scanId", scanID).Msg("created mock red team scan")

	return scanID
}

func (c *ClientImpl) pollForScanComplete(
	ctx context.Context,
	orgID string,
	scanID string,
) (*ScanStatus, *errors.Error) {
	numberOfPolls := 0

	for numberOfPolls <= maxPollAttempts {
		// TODO: remove later when not used
		time.Sleep(2 * time.Second)
		numberOfPolls++

		scanStatus, err := c.GetScan(ctx, orgID, scanID)
		if err != nil {
			return nil, err
		}

		if scanStatus.Attributes.Status == "completed" || scanStatus.Attributes.Status == "failed" {
			return scanStatus, nil
		}

		time.Sleep(pollInterval)
	}
	err := snyk_common_errors.NewServerError("Red team scan polling timed out.")
	return nil, &err
}

func (c *ClientImpl) setCommonHeaders(url string, req *http.Request) {
	requestID := uuid.New().String()
	c.logger.Debug().Msgf("making red-team api request to url: %s, requestId: %s", url, requestID)
	req.Header.Set("snyk-request-id", requestID)
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Content-Type", "application/vnd.api+json")
}
