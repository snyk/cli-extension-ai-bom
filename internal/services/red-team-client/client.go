package redteamclient

import (
	"bytes"
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

	errors "github.com/snyk/cli-extension-ai-bom/internal/errors"
)

const (
	DryRunScanID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
)

//revive:disable:exported // The interface must be called RedTeamClient to standardize.
type RedTeamClient interface {
	CheckAPIAvailability(ctx context.Context, orgID string) *errors.AiBomError
	CreateScan(ctx context.Context, orgID string, config RedTeamConfig) (string, *errors.AiBomError)
	GetScan(ctx context.Context, orgID, scanID string) (*ScanStatus, *errors.AiBomError)
	GetScanResults(ctx context.Context, orgID, scanID string) (string, *errors.AiBomError)
	ListScans(ctx context.Context, orgID string) ([]ScanSummary, *errors.AiBomError)
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

func (c *RedTeamClientImpl) CheckAPIAvailability(ctx context.Context, orgID string) *errors.AiBomError {
	_, err := c.createScan(ctx, orgID, RedTeamConfig{})
	return err
}

func (c *RedTeamClientImpl) CreateScan(ctx context.Context, orgID string, config RedTeamConfig) (string, *errors.AiBomError) {
	scanID, err := c.createScan(ctx, orgID, config)
	if err != nil {
		c.logger.Debug().Err(err.SnykError).Msg("error while creating the red team scan")
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
		c.logger.Debug().Err(err.SnykError).Msg("error while polling for the scan")
		return "", err
	}

	if scanStatus.Attributes.Status != "completed" {
		return "", errors.NewInternalError("Red team scan did not complete successfully")
	}

	return scanID, nil
}

func (c *RedTeamClientImpl) GetScan(ctx context.Context, orgID, scanID string) (*ScanStatus, *errors.AiBomError) {
	url := fmt.Sprintf("%s/rest/orgs/%s/ai-scans/%s?version=%s", c.baseURL, orgID, scanID, APIVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while building GetScan request")
		return nil, errors.NewInternalError(fmt.Sprintf("Error building GetScan request: %s", err.Error()))
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
		return nil, errors.NewInternalError(fmt.Sprintf("Failed to read GetScan response body: %s", err.Error()))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, c.redTeamErrorFromHTTPStatusCode("GetScan", resp.StatusCode, bodyBytes)
	}

	var scanStatus ScanStatus
	err = json.Unmarshal(bodyBytes, &scanStatus)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while unmarshaling ScanStatus")
		return nil, errors.NewInternalError(fmt.Sprintf("Failed to unmarshal ScanStatus: %s", err.Error()))
	}

	return &scanStatus, nil
}

func (c *RedTeamClientImpl) GetScanResults(ctx context.Context, orgID, scanID string) (string, *errors.AiBomError) {
	url := fmt.Sprintf("%s/rest/orgs/%s/ai-scans/%s/results?version=%s", c.baseURL, orgID, scanID, APIVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while building GetScanResults request")
		return "", errors.NewInternalError(fmt.Sprintf("Error building GetScanResults request: %s", err.Error()))
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
		return "", errors.NewInternalError(fmt.Sprintf("Failed to read GetScanResults response body: %s", err.Error()))
	}

	if resp.StatusCode != http.StatusOK {
		return "", c.redTeamErrorFromHTTPStatusCode("GetScanResults", resp.StatusCode, bodyBytes)
	}

	return string(bodyBytes), nil
}

func (c *RedTeamClientImpl) ListScans(ctx context.Context, orgID string) ([]ScanSummary, *errors.AiBomError) {
	url := fmt.Sprintf("%s/rest/orgs/%s/ai-scans?version=%s", c.baseURL, orgID, APIVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while building ListScans request")
		return nil, errors.NewInternalError(fmt.Sprintf("Error building ListScans request: %s", err.Error()))
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
		return nil, errors.NewInternalError(fmt.Sprintf("Failed to read ListScans response body: %s", err.Error()))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, c.redTeamErrorFromHTTPStatusCode("ListScans", resp.StatusCode, bodyBytes)
	}

	var scanList ScanListResponse
	err = json.Unmarshal(bodyBytes, &scanList)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while unmarshaling ScanListResponse")
		return nil, errors.NewInternalError(fmt.Sprintf("Failed to unmarshal ScanListResponse: %s", err.Error()))
	}

	return scanList.Data, nil
}

func (c *RedTeamClientImpl) redTeamErrorFromHTTPClientError(endPoint string, err error) *errors.AiBomError {
	c.logger.Debug().Err(err).Msg(fmt.Sprintf("%s request HTTP error", endPoint))
	if strings.Contains(strings.ToLower(err.Error()), "authentication") {
		return errors.NewUnauthorizedError(fmt.Sprintf("%s request failed with authentication error.", endPoint))
	}
	if strings.Contains(strings.ToLower(err.Error()), "forbidden") {
		return errors.NewForbiddenError(fmt.Sprintf("%s request failed with forbidden error.", endPoint))
	}
	return errors.NewInternalError(fmt.Sprintf("%s request HTTP error: %s", endPoint, err.Error()))
}

func (c *RedTeamClientImpl) redTeamErrorFromHTTPStatusCode(endPoint string, statusCode int, bodyBytes []byte) *errors.AiBomError {
	errMsg := fmt.Sprintf(
		"unexpected status code %d for %s", statusCode, endPoint)
	c.logger.Debug().Str("responseBody", string(bodyBytes)).Msg(errMsg)
	switch statusCode {
	case http.StatusUnauthorized:
		return errors.NewUnauthorizedError(errMsg)
	case http.StatusForbidden:
		return errors.NewForbiddenError(errMsg)
	default:
		return errors.NewInternalError(errMsg)
	}
}

func (c *RedTeamClientImpl) createScan(
	ctx context.Context,
	orgID string,
	config RedTeamConfig,
) (string, *errors.AiBomError) {
	c.logger.Debug().Msg("creating red team scan")

	body := CreateScanRequestBody{Data: config}

	reqBytes, err := json.Marshal(body)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while marshaling request body")
		return "", errors.NewInternalError(fmt.Sprintf("Error marshaling request body: %s", err.Error()))
	}
	url := fmt.Sprintf("%s/rest/orgs/%s/ai-scans?version=%s", c.baseURL, orgID, APIVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(reqBytes))
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while building CreateScan request")
		return "", errors.NewInternalError(fmt.Sprintf("Error building CreateScan request: %s", err.Error()))
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
		return "", errors.NewInternalError(fmt.Sprintf("Failed to read CreateScan response body: %s", err.Error()))
	}

	if resp.StatusCode != http.StatusAccepted {
		return "", c.redTeamErrorFromHTTPStatusCode("CreateScan", resp.StatusCode, bodyBytes)
	}

	var scanResp CreateScanResponseBody
	err = json.Unmarshal(bodyBytes, &scanResp)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while unmarshaling CreateScanResponseBody")
		return "", errors.NewInternalError(fmt.Sprintf("Failed to unmarshal CreateScanResponseBody: %s", err.Error()))
	}

	scanID := scanResp.Data.Id.String()
	c.logger.Debug().Str("scanId", scanID).Msg("created red team scan")

	return scanID, nil
}

func (c *RedTeamClientImpl) pollForScanComplete(
	ctx context.Context,
	orgID string,
	scanID string,
) (*ScanStatus, *errors.AiBomError) {
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
	return nil, errors.NewInternalError("Red team scan polling timed out.")
}

func (c *RedTeamClientImpl) setCommonHeaders(url string, req *http.Request) {
	requestID := uuid.New().String()
	c.logger.Debug().Msgf("making red-team api request to url: %s, requestId: %s", url, requestID)
	req.Header.Set("snyk-request-id", requestID)
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Content-Type", "application/vnd.api+json")
}
