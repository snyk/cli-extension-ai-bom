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

	snyk_common_errors "github.com/snyk/error-catalog-golang-public/snyk"
	errors "github.com/snyk/error-catalog-golang-public/snyk_errors"
)

type RedTeamClient interface {
	RunScan(ctx context.Context, orgID string, config *RedTeamConfig) (string, *errors.Error)
	GetScan(ctx context.Context, orgID, scanID string) (*AIScan, *errors.Error)
	GetScanResults(ctx context.Context, orgID, scanID string) (GetAIVulnerabilitiesResponseData, *errors.Error)
}

type ClientImpl struct {
	userAgent     string
	baseURL       string
	httpClient    *http.Client
	logger        *zerolog.Logger
	userInterface ui.UserInterface
}

var _ RedTeamClient = (*ClientImpl)(nil)

const (
	maxPollAttempts = 720
	pollInterval    = 5000 * time.Millisecond

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

func (c *ClientImpl) RunScan(ctx context.Context, orgID string, config *RedTeamConfig) (string, *errors.Error) {
	progressBar := c.userInterface.NewProgressBar()
	progressBar.SetTitle(fmt.Sprintf("Starting a scan against %s...", config.Target.Name))

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

	scanID, err := c.createScan(ctx, orgID, config)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while creating scan")
		return "", err
	}

	scanStatus, err := c.pollForScanComplete(ctx, orgID, scanID, progressBar)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while polling for the scan")
		return "", err
	}

	if scanStatus.Status == AIScanStatusFailed {
		err := snyk_common_errors.NewServerError("Red team scan has failed.")
		return "", &err
	}

	progressBar.SetTitle("Scan completed")
	if progressErr := progressBar.UpdateProgress(1.0); progressErr != nil {
		c.logger.Debug().Err(progressErr).Msg("Failed to update progress bar")
	}

	return scanID, nil
}

func (c *ClientImpl) GetScan(ctx context.Context, orgID, scanID string) (*AIScan, *errors.Error) {
	url := fmt.Sprintf("%s/hidden/orgs/%s/ai_scans/%s?version=%s", c.baseURL, orgID, scanID, APIVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while building GetScan request")
		err := snyk_common_errors.NewServerError(fmt.Sprintf("Error building GetScan request: %s", err.Error()))
		return nil, &err
	}

	// Make the request retry-able for HTTP/2
	req.GetBody = func() (io.ReadCloser, error) {
		return http.NoBody, nil
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

	scanRespBody := GetAIScanResponse{}
	err = json.Unmarshal(bodyBytes, &scanRespBody)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while unmarshaling GetScanResponseBody")
		err := snyk_common_errors.NewServerError(fmt.Sprintf("Failed to unmarshal GetScanResponseBody: %s", err.Error()))
		return nil, &err
	}

	return &scanRespBody.Data, nil
}

func (c *ClientImpl) GetScanResults(ctx context.Context, orgID, scanID string) (GetAIVulnerabilitiesResponseData, *errors.Error) {
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

	url := fmt.Sprintf("%s/hidden/orgs/%s/ai_scans/%s/vulnerabilities?version=%s", c.baseURL, orgID, scanID, APIVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while building GetScan request")
		err := snyk_common_errors.NewBadRequestError(fmt.Sprintf("Error building GetScan request: %s", err.Error()))
		return GetAIVulnerabilitiesResponseData{}, &err
	}

	c.setCommonHeaders(url, req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return GetAIVulnerabilitiesResponseData{}, c.redTeamErrorFromHTTPClientError("GetScanResults", err)
	}

	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while reading GetScanResults response body")
		err := snyk_common_errors.NewServerError(fmt.Sprintf("Failed to read GetScanResults response body: %s", err.Error()))
		return GetAIVulnerabilitiesResponseData{}, &err
	}

	if resp.StatusCode != http.StatusOK {
		return GetAIVulnerabilitiesResponseData{}, c.redTeamErrorFromHTTPStatusCode("GetScanResults", resp.StatusCode, bodyBytes)
	}

	scanRespBody := GetAIVulnerabilitiesResponse{}
	err = json.Unmarshal(bodyBytes, &scanRespBody)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while unmarshaling GetScanResultsResponseBody")
		err := snyk_common_errors.NewServerError(fmt.Sprintf("Failed to unmarshal GetScanResultsResponseBody: %s", err.Error()))
		return GetAIVulnerabilitiesResponseData{}, &err
	}

	progressBar.SetTitle("Scan results retrieved")

	if err := progressBar.UpdateProgress(1.0); err != nil {
		c.logger.Debug().Err(err).Msg("Failed to update progress bar")
	}

	return scanRespBody.Data, nil
}

func (c *ClientImpl) createScan(
	ctx context.Context,
	orgID string,
	redTeamConfig *RedTeamConfig,
) (string, *errors.Error) {
	c.logger.Debug().Msg("creating red team scan")

	request := CreateAIScanRequest{
		Data: CreateAIScanRequestData{
			Target: AIScanTarget{
				Name:     redTeamConfig.Target.Name,
				Type:     redTeamConfig.Target.Type,
				Context:  redTeamConfig.Target.Context,
				Settings: redTeamConfig.Target.Settings,
			},
			Options: AIScanOptions{
				VulnDefinitions: redTeamConfig.Options.VulnDefinitions,
			},
		},
	}

	body := request

	reqBytes, err := json.Marshal(body)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while marshaling request body")
		badRequestErr := snyk_common_errors.NewBadRequestError(fmt.Sprintf("Error marshaling request body: %s", err.Error()))
		return "", &badRequestErr
	}

	url := fmt.Sprintf("%s/hidden/orgs/%s/ai_scans?version=%s", c.baseURL, orgID, APIVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(reqBytes))
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while building red team scan request")
		badRequestErr := snyk_common_errors.NewBadRequestError(fmt.Sprintf("Error building red team request: %s", err.Error()))
		return "", &badRequestErr
	}

	c.setCommonHeaders(url, req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", c.redTeamErrorFromHTTPClientError(url, err)
	}

	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while reading RunScan response body")
		err := snyk_common_errors.NewServerError(fmt.Sprintf("Failed to read RunScan response body: %s", err.Error()))
		return "", &err
	}

	if resp.StatusCode != http.StatusCreated {
		return "", c.redTeamErrorFromHTTPStatusCode("RunScan", resp.StatusCode, bodyBytes)
	}

	scanRespBody := CreateAIScanResponse{}
	err = json.Unmarshal(bodyBytes, &scanRespBody)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while unmarshaling CreateScanResponseBody")
		err := snyk_common_errors.NewServerError(fmt.Sprintf("Failed to unmarshal CreateScanResponseBody: %s", err.Error()))
		return "", &err
	}

	scanID := scanRespBody.Data.ID
	c.logger.Debug().Str("scanID", scanID).Msg("created red team scan")

	return scanID, nil
}

func (c *ClientImpl) pollForScanComplete(
	ctx context.Context,
	orgID string,
	scanID string,
	scanProgressBar ui.ProgressBar,
) (*AIScan, *errors.Error) {
	numberOfPolls := 0

	for numberOfPolls <= maxPollAttempts {
		numberOfPolls++

		scanData, err := c.GetScan(ctx, orgID, scanID)
		if err != nil {
			return nil, err
		}

		if scanData.Feedback.Status != nil {
			scanProgressBar.SetTitle("Running a scan... It might take a while.")
			if err := scanProgressBar.UpdateProgress(float64(*scanData.Feedback.Status.Done) / float64(*scanData.Feedback.Status.Total)); err != nil {
				c.logger.Debug().Err(err).Msg("Failed to update progress bar")
			}
		}

		c.logger.Debug().
			Str("scanID", scanID).
			Str("status", string(scanData.Status)).
			Msgf("Polling results for scan")

		if scanData.Status == AIScanStatusCompleted || scanData.Status == AIScanStatusFailed {
			return scanData, nil
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

func (c *ClientImpl) redTeamErrorFromHTTPClientError(endPoint string, err error) *errors.Error {
	c.logger.Debug().Err(err).Msg(fmt.Sprintf("%s request HTTP error", endPoint))
	if strings.Contains(strings.ToLower(err.Error()), "authentication") {
		authErr := snyk_common_errors.NewUnauthorisedError(fmt.Sprintf("%s request failed with authentication error.", endPoint))
		return &authErr
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
	default:
		serverErr := snyk_common_errors.NewServerError(errMsg)
		return &serverErr
	}
}
