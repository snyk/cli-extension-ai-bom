package redteamclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	snyk_common_errors "github.com/snyk/error-catalog-golang-public/snyk"

	redteam_errors "github.com/snyk/cli-extension-ai-bom/internal/errors/redteam"
)

type RedTeamClient interface {
	CreateScan(ctx context.Context, orgID string, config *RedTeamConfig) (string, *redteam_errors.RedTeamError)
	GetScan(ctx context.Context, orgID, scanID string) (*AIScan, *redteam_errors.RedTeamError)
	GetScanResults(ctx context.Context, orgID, scanID string) (GetAIVulnerabilitiesResponseData, *redteam_errors.RedTeamError)
}

type ClientImpl struct {
	userAgent  string
	baseURL    string
	httpClient *http.Client
	logger     *zerolog.Logger
}

var _ RedTeamClient = (*ClientImpl)(nil)

func NewRedTeamClient(
	logger *zerolog.Logger,
	httpClient *http.Client,
	userAgent string,
	baseURL string,
) *ClientImpl {
	httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		// Return http.ErrUseLastResponse to not follow redirects
		return http.ErrUseLastResponse
	}
	return &ClientImpl{
		userAgent:  userAgent,
		baseURL:    baseURL,
		httpClient: httpClient,
		logger:     logger,
	}
}

var APIVersion = "2024-10-15"

func (c *ClientImpl) GetScan(ctx context.Context, orgID, scanID string) (*AIScan, *redteam_errors.RedTeamError) {
	url := fmt.Sprintf("%s/hidden/orgs/%s/ai_scans/%s?version=%s", c.baseURL, orgID, scanID, APIVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while building GetScan request")
		return nil, redteam_errors.NewBadRequestError(fmt.Sprintf("Error building GetScan request: %s", err.Error()))
	}

	// Make the request retry-able for HTTP/2
	req.GetBody = func() (io.ReadCloser, error) {
		return http.NoBody, nil
	}

	c.setCommonHeaders(url, req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, c.redTeamErrorFromHTTPClientError(url, err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while reading GetScan response body")
		return nil, redteam_errors.NewBadRequestError(fmt.Sprintf("Error building GetScan request: %s", err.Error()))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, c.redTeamErrorFromHTTPStatusCode("GetScan", resp.StatusCode, bodyBytes)
	}

	scanRespBody := GetAIScanResponse{}
	err = json.Unmarshal(bodyBytes, &scanRespBody)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while unmarshaling GetScanResponseBody")
		err := redteam_errors.NewServerError(fmt.Sprintf("Failed to unmarshal GetScanResponseBody: %s", err.Error()))
		return nil, err
	}

	return &scanRespBody.Data, nil
}

func (c *ClientImpl) GetScanResults(ctx context.Context, orgID, scanID string) (GetAIVulnerabilitiesResponseData, *redteam_errors.RedTeamError) {
	url := fmt.Sprintf("%s/hidden/orgs/%s/ai_scans/%s/vulnerabilities?version=%s", c.baseURL, orgID, scanID, APIVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while building GetScan request")
		err := snyk_common_errors.NewBadRequestError(fmt.Sprintf("Error building GetScan request: %s", err.Error()))
		return GetAIVulnerabilitiesResponseData{}, redteam_errors.NewBadRequestError(fmt.Sprintf("Error building GetScan request: %s", err.Error()))
	}

	c.setCommonHeaders(url, req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return GetAIVulnerabilitiesResponseData{}, c.redTeamErrorFromHTTPClientError(url, err)
	}

	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while reading GetScanResults response body")
		err := redteam_errors.NewServerError(fmt.Sprintf("Failed to read GetScanResults response body: %s", err.Error()))
		return GetAIVulnerabilitiesResponseData{}, err
	}

	if resp.StatusCode != http.StatusOK {
		return GetAIVulnerabilitiesResponseData{}, c.redTeamErrorFromHTTPStatusCode("GetScanResults", resp.StatusCode, bodyBytes)
	}

	scanRespBody := GetAIVulnerabilitiesResponse{}
	err = json.Unmarshal(bodyBytes, &scanRespBody)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while unmarshaling GetScanResultsResponseBody")
		err := redteam_errors.NewServerError(fmt.Sprintf("Failed to unmarshal GetScanResultsResponseBody: %s", err.Error()))
		return GetAIVulnerabilitiesResponseData{}, err
	}

	return scanRespBody.Data, nil
}

func (c *ClientImpl) CreateScan(
	ctx context.Context,
	orgID string,
	redTeamConfig *RedTeamConfig,
) (string, *redteam_errors.RedTeamError) {
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
		badRequestErr := redteam_errors.NewBadRequestError(fmt.Sprintf("Error marshaling request body: %s", err.Error()))
		return "", badRequestErr
	}

	url := fmt.Sprintf("%s/hidden/orgs/%s/ai_scans?version=%s", c.baseURL, orgID, APIVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(reqBytes))
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while building red team scan request")
		badRequestErr := redteam_errors.NewBadRequestError(fmt.Sprintf("Error building red team request: %s", err.Error()))
		return "", badRequestErr
	}

	c.setCommonHeaders(url, req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", c.redTeamErrorFromHTTPClientError(url, err)
	}

	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while reading CreateScan response body")
		err := snyk_common_errors.NewServerError(fmt.Sprintf("Failed to read CreateScan response body: %s", err.Error()))
		return "", redteam_errors.NewServerError(fmt.Sprintf("Failed to read CreateScan response body: %s", err.Error()))
	}

	if resp.StatusCode != http.StatusCreated {
		return "", c.redTeamErrorFromHTTPStatusCode("CreateScan", resp.StatusCode, bodyBytes)
	}

	scanRespBody := CreateAIScanResponse{}
	err = json.Unmarshal(bodyBytes, &scanRespBody)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while unmarshaling CreateScanResponseBody")
		err := snyk_common_errors.NewServerError(fmt.Sprintf("Failed to unmarshal CreateScanResponseBody: %s", err.Error()))
		return "", redteam_errors.NewServerError(fmt.Sprintf("Failed to unmarshal CreateScanResponseBody: %s", err.Error()))
	}

	scanID := scanRespBody.Data.ID
	c.logger.Debug().Str("scanID", scanID).Msg("created red team scan")

	return scanID, nil
}

func (c *ClientImpl) setCommonHeaders(url string, req *http.Request) {
	requestID := uuid.New().String()
	c.logger.Debug().Msgf("making red-team api request to url: %s, requestId: %s", url, requestID)
	req.Header.Set("snyk-request-id", requestID)
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Content-Type", "application/vnd.api+json")
}

func (c *ClientImpl) redTeamErrorFromHTTPStatusCode(endPoint string, statusCode int, bodyBytes []byte) *redteam_errors.RedTeamError {
	errMsg := fmt.Sprintf(
		"unexpected status code %d for %s", statusCode, endPoint)
	c.logger.Debug().Str("responseBody", string(bodyBytes)).Msg(errMsg)
	switch statusCode {
	case http.StatusUnauthorized:
		authErr := redteam_errors.NewUnauthorizedError(errMsg)
		return authErr
	default:
		serverErr := redteam_errors.NewServerError(errMsg)
		return serverErr
	}
}

func (c *ClientImpl) redTeamErrorFromHTTPClientError(endPoint string, err error) *redteam_errors.RedTeamError {
	c.logger.Debug().Err(err).Msg(fmt.Sprintf("%s request HTTP error", endPoint))
	if strings.Contains(strings.ToLower(err.Error()), "authentication") {
		return redteam_errors.NewUnauthorizedError(fmt.Sprintf("%s request failed with authentication error.", endPoint))
	}
	return redteam_errors.NewHTTPClientError(`Couldn't make the request to Snyk. An error is returned if caused by client policy ` +
		`(such as CheckRedirect), or failure to speak HTTP (such as a network connectivity problem).`)
}
