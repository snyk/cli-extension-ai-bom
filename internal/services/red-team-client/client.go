package redteamclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	CreateScan(ctx context.Context, orgID string, config RedTeamConfig) (string, *errors.Error)
	GetScan(ctx context.Context, orgID, scanID string) (*ScanStatus, *errors.Error)
	GetScanResults(ctx context.Context, orgID, scanID string) (string, *errors.Error)
	ListScans(ctx context.Context, orgID string) ([]ScanSummary, *errors.Error)
}

type RedTeamClientImpl struct {
	userAgent     string
	baseURL       string
	httpClient    *http.Client
	logger        *zerolog.Logger
	userInterface ui.UserInterface
}

var _ RedTeamClient = (*RedTeamClientImpl)(nil) // Assert that RedTeamClientImpl implements RedTeamClient

const (
	maxPollAttempts = 7200
	pollInterval    = 500 * time.Millisecond
)

func NewRedTeamClient(
	logger *zerolog.Logger,
	httpClient *http.Client,
	userInterface ui.UserInterface,
	userAgent string,
	baseURL string,
) *RedTeamClientImpl {
	httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		// Return http.ErrUseLastResponse to not follow redirects
		return http.ErrUseLastResponse
	}
	return &RedTeamClientImpl{
		userAgent:     userAgent,
		baseURL:       baseURL,
		httpClient:    httpClient,
		logger:        logger,
		userInterface: userInterface,
	}
}

var APIVersion = "2024-10-15"

func (c *RedTeamClientImpl) CheckAPIAvailability(ctx context.Context, orgID string) *errors.Error {
	// TODO(pkey): implement this checking logic later
	return nil
}

func (c *RedTeamClientImpl) CreateScan(ctx context.Context, orgID string, config RedTeamConfig) (string, *errors.Error) {
	scanID, err := c.createScan(ctx, orgID, config)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while creating the red team scan")
		return "", err
	}

	progressBar := c.userInterface.NewProgressBar()
	progressBar.SetTitle("Red Team Scan")
	progressErr := progressBar.UpdateProgress(ui.InfiniteProgress)
	if progressErr != nil {
		c.logger.Debug().Err(progressErr).Msg("Failed to update progress bar")
	}
	defer func() {
		progressErr = progressBar.Clear()
		if progressErr != nil {
			c.logger.Debug().Err(progressErr).Msg("Failed to clear progress bar")
		}
	}()

	scanStatus, err := c.pollForScanComplete(ctx, orgID, scanID)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while polling for the scan")
		return "", err
	}

	if scanStatus.Attributes.Status != "completed" {
		err := snyk_common_errors.NewServerError("Red team scan did not complete successfully")
		return "", &err
	}

	return scanID, nil
}

func (c *RedTeamClientImpl) GetScan(ctx context.Context, orgID, scanID string) (*ScanStatus, *errors.Error) {
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
		Id:   scanUUID,
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

	// TODO: Uncomment when service is available
	/*
		url := fmt.Sprintf("%s/rest/orgs/%s/ai-scans/%s?version=%s", c.baseURL, orgID, scanID, APIVersion)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
		if err != nil {
			c.logger.Debug().Err(err).Msg("error while building GetScan request")
			err := snyk_common_errors.NewServerError(fmt.Sprintf("Error building GetScan request: %s", err.Error()))
			return nil, &err
		}
		c.setCommonHeaders(url, req)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, c.redTeamErrorFromHTTPClientError("GetScan", err)
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			c.logger.Debug().Err(err).Msg("error while reading GetScan response body")
			err := snyk_common_errors.NewServerError(fmt.Sprintf("Failed to read GetScan response body: %s", err.Error()))
			return nil, &err
		}

		if resp.StatusCode != http.StatusOK {
			return nil, c.redTeamErrorFromHTTPStatusCode("GetScan", resp.StatusCode, bodyBytes)
		}

		var scanStatus ScanStatus
		err = json.Unmarshal(bodyBytes, &scanStatus)
		if err != nil {
			c.logger.Debug().Err(err).Msg("error while unmarshaling ScanStatus")
			err := snyk_common_errors.NewServerError(fmt.Sprintf("Failed to unmarshal ScanStatus: %s", err.Error()))
			return nil, &err
		}

		return &scanStatus, nil
	*/
}

func (c *RedTeamClientImpl) GetScanResults(ctx context.Context, orgID, scanID string) (string, *errors.Error) {
	// Mock implementation - service doesn't exist yet
	c.logger.Debug().Str("scanId", scanID).Msg("returning mock scan results")

	// Return mock JSON results
	mockResults := `{
		"data": {
			"id": "` + scanID + `",
			"type": "ai-scan-results",
			"attributes": {
				"status": "completed",
				"results": {
					"vulnerabilities_found": 3,
					"attacks_performed": ["sql_injection", "xss", "csrf"],
					"severity": "high",
					"recommendations": [
						"Implement input validation",
						"Use parameterized queries",
						"Add CSRF tokens"
					]
				}
			}
		}
	}`

	return mockResults, nil

	// TODO: Uncomment when service is available
	/*
		url := fmt.Sprintf("%s/rest/orgs/%s/ai-scans/%s/results?version=%s", c.baseURL, orgID, scanID, APIVersion)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
		if err != nil {
			c.logger.Debug().Err(err).Msg("error while building GetScanResults request")
			serverErr := snyk_common_errors.NewServerError(fmt.Sprintf("Error building GetScanResults request: %s", err.Error()))
			return "", &serverErr
		}
		c.setCommonHeaders(url, req)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return "", c.redTeamErrorFromHTTPClientError("GetScanResults", err)
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			c.logger.Debug().Err(err).Msg("error while reading GetScanResults response body")
			serverErr := snyk_common_errors.NewServerError(fmt.Sprintf("Failed to read GetScanResults response body: %s", err.Error()))
			return "", &serverErr
		}

		if resp.StatusCode != http.StatusOK {
			return "", c.redTeamErrorFromHTTPStatusCode("GetScanResults", resp.StatusCode, bodyBytes)
		}

		return string(bodyBytes), nil
	*/
}

func (c *RedTeamClientImpl) ListScans(ctx context.Context, orgID string) ([]ScanSummary, *errors.Error) {
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

func (c *RedTeamClientImpl) redTeamErrorFromHTTPClientError(endPoint string, err error) *errors.Error {
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

func (c *RedTeamClientImpl) redTeamErrorFromHTTPStatusCode(endPoint string, statusCode int, bodyBytes []byte) *errors.Error {
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

func (c *RedTeamClientImpl) createScan(
	ctx context.Context,
	orgID string,
	config RedTeamConfig,
) (string, *errors.Error) {
	// Mock implementation - service doesn't exist yet
	c.logger.Debug().Msg("creating mock red team scan")

	// Generate a new UUID for the mock scan
	scanID := uuid.New().String()
	c.logger.Debug().Str("scanId", scanID).Msg("created mock red team scan")

	return scanID, nil

	// TODO: Uncomment when service is available
	/*
		c.logger.Debug().Msg("creating red team scan")

		body := CreateScanRequestBody{Data: config}

		reqBytes, err := json.Marshal(body)
		if err != nil {
			c.logger.Debug().Err(err).Msg("error while marshaling request body")
			err := snyk_common_errors.NewServerError(fmt.Sprintf("Error marshaling request body: %s", err.Error()))
			return "", &err
		}
		url := fmt.Sprintf("%s/rest/orgs/%s/ai-scans?version=%s", c.baseURL, orgID, APIVersion)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(reqBytes))
		if err != nil {
			c.logger.Debug().Err(err).Msg("error while building CreateScan request")
			err := snyk_common_errors.NewServerError(fmt.Sprintf("Error building CreateScan request: %s", err.Error()))
			return "", &err
		}

		c.setCommonHeaders(url, req)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return "", c.redTeamErrorFromHTTPClientError("CreateScan", err)
		}

		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			c.logger.Debug().Err(err).Msg("error while reading CreateScan response body")
			err := snyk_common_errors.NewServerError(fmt.Sprintf("Failed to read CreateScan response body: %s", err.Error()))
			return "", &err
		}

		if resp.StatusCode != http.StatusAccepted {
			return "", c.redTeamErrorFromHTTPStatusCode("CreateScan", resp.StatusCode, bodyBytes)
		}

		var scanResp CreateScanResponseBody
		err = json.Unmarshal(bodyBytes, &scanResp)
		if err != nil {
			c.logger.Debug().Err(err).Msg("error while unmarshaling CreateScanResponseBody")
			err := snyk_common_errors.NewServerError(fmt.Sprintf("Failed to unmarshal CreateScanResponseBody: %s", err.Error()))
			return "", &err
		}

		scanID := scanResp.Data.Id.String()
		c.logger.Debug().Str("scanId", scanID).Msg("created red team scan")

		return scanID, nil
	*/
}

func (c *RedTeamClientImpl) pollForScanComplete(
	ctx context.Context,
	orgID string,
	scanID string,
) (*ScanStatus, *errors.Error) {
	numberOfPolls := 0

	for numberOfPolls <= maxPollAttempts {
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

func (c *RedTeamClientImpl) setCommonHeaders(url string, req *http.Request) {
	requestID := uuid.New().String()
	c.logger.Debug().Msgf("making red-team api request to url: %s, requestId: %s", url, requestID)
	req.Header.Set("snyk-request-id", requestID)
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Content-Type", "application/vnd.api+json")
}
