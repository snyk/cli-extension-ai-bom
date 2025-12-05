package redteamclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	snyk_common_errors "github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"

	redteam_errors "github.com/snyk/cli-extension-ai-bom/internal/errors/redteam"
)

type RedTeamClient interface {
	CreateScan(ctx context.Context, orgID string, config *RedTeamConfig) (string, *redteam_errors.RedTeamError)
	GetScan(ctx context.Context, orgID, scanID string) (*AIScan, *redteam_errors.RedTeamError)
	GetScanResults(ctx context.Context, orgID, scanID string) (GetAIVulnerabilitiesResponseData, *redteam_errors.RedTeamError)
	CreateScanningAgent(ctx context.Context, orgID, name string) (*AIScanningAgent, *redteam_errors.RedTeamError)
	GenerateScanningAgentConfig(ctx context.Context, orgID, scanningAgentID string) (*GenerateAIScanningAgentConfigData, *redteam_errors.RedTeamError)
	ListScanningAgents(ctx context.Context, orgID string) ([]AIScanningAgent, *redteam_errors.RedTeamError)
	DeleteScanningAgent(ctx context.Context, orgID, scanningAgentID string) *redteam_errors.RedTeamError
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
				ScanningAgent:   redTeamConfig.Options.ScanningAgent,
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

// Handles HttpClient errors. Snyk's HttpClient overrides the logic that would return a non-nil response that has a valid status code
// Instead, it returns a snyk_errors.Error object. This handles that error as a http client error.
func (c *ClientImpl) redTeamErrorFromHTTPClientError(endPoint string, err error) *redteam_errors.RedTeamError {
	c.logger.Debug().Err(err).Msg(fmt.Sprintf("%s request HTTP error", endPoint))

	// The idea here is to do less custom error handling in the CLI and leave this to the backend
	var snykErr snyk_errors.Error
	if errors.As(err, &snykErr) {
		c.logger.Debug().
			Str("error_type", fmt.Sprintf("%T", snykErr)).
			Str("detail", snykErr.Detail).
			Int("status_code", snykErr.StatusCode).
			Msg("extracted snyk error")

		var errorMsg string
		switch {
		case snykErr.Detail != "":
			errorMsg = snykErr.Detail
		case snykErr.Title != "":
			errorMsg = snykErr.Title
		default:
			errorMsg = err.Error()
		}

		switch snykErr.StatusCode {
		case http.StatusBadRequest:
			return redteam_errors.NewBadRequestError(errorMsg)
		case http.StatusInternalServerError:
			// Override the error message to be more user friendly
			return redteam_errors.NewServerError("Server responded with a 500. Please try again later or contact support.")
		}
	}

	if strings.Contains(strings.ToLower(err.Error()), "authentication") {
		return redteam_errors.NewUnauthorizedError("Failed to authenticate to red teaming API.")
	}
	// NOTE(pkey): This should be handled by the Cerberus (it doesn't return permissions that are missing)
	if strings.Contains(strings.ToLower(err.Error()), "forbidden") {
		return redteam_errors.NewForbiddenError("Red teaming API resource is forbidden. You need at least Org Edit rights.")
	}
	return redteam_errors.NewHTTPClientError(`Failed to reach our API. It might be a permission issue or a network connectivity problem. `)
}

func (c *ClientImpl) CreateScanningAgent(ctx context.Context, orgID, name string) (*AIScanningAgent, *redteam_errors.RedTeamError) {
	request := CreateAIScanningAgentRequest{
		Data: AIScanningAgentInput{
			Name: name,
		},
	}

	reqBytes, err := json.Marshal(request)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while marshaling request body")
		badRequestErr := redteam_errors.NewBadRequestError(fmt.Sprintf("Error marshaling request body: %s", err.Error()))
		return nil, badRequestErr
	}

	url := fmt.Sprintf("%s/hidden/orgs/%s/scanning_agents?version=%s", c.baseURL, orgID, APIVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(reqBytes))
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while building red team scanning agent request")
		badRequestErr := redteam_errors.NewBadRequestError(fmt.Sprintf("Error building red team scanning agent request: %s", err.Error()))
		return nil, badRequestErr
	}

	c.setCommonHeaders(url, req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, c.redTeamErrorFromHTTPClientError("CreateScanningAgent", err)
	}

	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while reading CreateScanningAgent response body")
		err := redteam_errors.NewServerError(fmt.Sprintf("Failed to read CreateScanningAgent response body: %s", err.Error()))
		return nil, err
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, c.redTeamErrorFromHTTPStatusCode("CreateScanningAgent", resp.StatusCode, bodyBytes)
	}

	scanningAgentRespBody := CreateAIScanningAgentResponse{}
	err = json.Unmarshal(bodyBytes, &scanningAgentRespBody)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while unmarshaling CreateScanningAgentResponseBody")
		err := redteam_errors.NewServerError(fmt.Sprintf("Failed to unmarshal CreateScanningAgentResponseBody: %s", err.Error()))
		return nil, err
	}
	c.logger.Debug().Str("scanningAgentID", scanningAgentRespBody.Data.ID).Msg("created red team scanning agent")

	return &scanningAgentRespBody.Data, nil
}

func (c *ClientImpl) GenerateScanningAgentConfig(
	ctx context.Context,
	orgID, scanningAgentID string,
) (*GenerateAIScanningAgentConfigData, *redteam_errors.RedTeamError) {
	url := fmt.Sprintf("%s/hidden/orgs/%s/scanning_agents/%s/generate?version=%s", c.baseURL, orgID, scanningAgentID, APIVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, http.NoBody)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while building red team scanning agent config request")
		badRequestErr := redteam_errors.NewBadRequestError(fmt.Sprintf("Error building red team scanning agent config request: %s", err.Error()))
		return nil, badRequestErr
	}

	c.setCommonHeaders(url, req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, c.redTeamErrorFromHTTPClientError("GenerateScanningAgentConfig", err)
	}

	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while reading GenerateScanningAgentConfig response body")
		err := redteam_errors.NewServerError(fmt.Sprintf("Failed to read GenerateScanningAgentConfig response body: %s", err.Error()))
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, c.redTeamErrorFromHTTPStatusCode("GenerateScanningAgentConfig", resp.StatusCode, bodyBytes)
	}

	scanningAgentConfigRespBody := GenerateAIScanningAgentConfigResponse{}
	err = json.Unmarshal(bodyBytes, &scanningAgentConfigRespBody)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while unmarshaling GenerateScanningAgentConfigResponseBody")
		err := redteam_errors.NewServerError(fmt.Sprintf("Failed to unmarshal GenerateScanningAgentConfigResponseBody: %s", err.Error()))
		return nil, err
	}
	c.logger.Debug().Str("scanningAgentID", scanningAgentID).Msg("generated red team scanning agent config")

	return &scanningAgentConfigRespBody.Data, nil
}

func (c *ClientImpl) ListScanningAgents(ctx context.Context, orgID string) ([]AIScanningAgent, *redteam_errors.RedTeamError) {
	url := fmt.Sprintf("%s/hidden/orgs/%s/scanning_agents?version=%s", c.baseURL, orgID, APIVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while building red team scanning agents list request")
		badRequestErr := redteam_errors.NewBadRequestError(fmt.Sprintf("Error building red team scanning agents list request: %s", err.Error()))
		return nil, badRequestErr
	}

	c.setCommonHeaders(url, req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, c.redTeamErrorFromHTTPClientError("ListScanningAgents", err)
	}

	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while reading ListScanningAgents response body")
		err := redteam_errors.NewServerError(fmt.Sprintf("Failed to read ListScanningAgents response body: %s", err.Error()))
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, c.redTeamErrorFromHTTPStatusCode("ListScanningAgents", resp.StatusCode, bodyBytes)
	}

	scanningAgentsRespBody := ListAIScanningAgentsResponse{}
	err = json.Unmarshal(bodyBytes, &scanningAgentsRespBody)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while unmarshaling ListScanningAgentsResponseBody")
		err := redteam_errors.NewServerError(fmt.Sprintf("Failed to unmarshal ListScanningAgentsResponseBody: %s", err.Error()))
		return nil, err
	}
	scanningAgentIDs := make([]string, len(scanningAgentsRespBody.Data))
	for i, scanningAgent := range scanningAgentsRespBody.Data {
		scanningAgentIDs[i] = scanningAgent.ID
	}
	c.logger.Debug().Interface("scanningAgentIDs", scanningAgentIDs).Msg("listed red team scanning agents")

	return scanningAgentsRespBody.Data, nil
}

func (c *ClientImpl) DeleteScanningAgent(ctx context.Context, orgID, scanningAgentID string) *redteam_errors.RedTeamError {
	url := fmt.Sprintf("%s/hidden/orgs/%s/scanning_agents/%s?version=%s", c.baseURL, orgID, scanningAgentID, APIVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, http.NoBody)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while building red team scanning agent delete request")
		badRequestErr := redteam_errors.NewBadRequestError(fmt.Sprintf("Error building red team scanning agent delete request: %s", err.Error()))
		return badRequestErr
	}

	c.setCommonHeaders(url, req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return c.redTeamErrorFromHTTPClientError("DeleteScanningAgent", err)
	}

	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while reading DeleteScanningAgent response body")
		err := redteam_errors.NewServerError(fmt.Sprintf("Failed to read DeleteScanningAgent response body: %s", err.Error()))
		return err
	}

	if resp.StatusCode != http.StatusNoContent {
		return c.redTeamErrorFromHTTPStatusCode("DeleteScanningAgent", resp.StatusCode, bodyBytes)
	}
	c.logger.Debug().Str("scanningAgentID", scanningAgentID).Msg("deleted red team scanning agent")

	return nil
}
