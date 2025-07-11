package aibomclient

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

//revive:disable:exported // The interface must be called AiBomClient to standardize.
type AiBomClient interface {
	GenerateAIBOM(
		ctx context.Context,
		orgID,
		bundleHash string,
	) (string, *errors.AiBomError)
}

type AIBOMClientImpl struct {
	userAgent     string
	baseURL       string
	authToken     string
	httpClient    *http.Client
	logger        *zerolog.Logger
	userInterface ui.UserInterface
}

var _ AiBomClient = (*AIBOMClientImpl)(nil) // Assert that AIBOMClient implements Client

const (
	maxPollAttempts = 7200
	pollInterval    = 500 * time.Millisecond
)

func NewAiBomClient(
	logger *zerolog.Logger,
	userInterface ui.UserInterface,
	userAgent,
	baseURL,
	authToken string,
) *AIBOMClientImpl {
	httpClient := http.Client{}
	httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		// Return http.ErrUseLastResponse to not follow redirects
		return http.ErrUseLastResponse
	}
	return &AIBOMClientImpl{
		userAgent:     userAgent,
		baseURL:       baseURL,
		authToken:     authToken,
		httpClient:    &httpClient,
		logger:        logger,
		userInterface: userInterface,
	}
}

var APIVersion = "2024-10-15"

func (c *AIBOMClientImpl) GenerateAIBOM(ctx context.Context, orgID, bundleHash string) (string, *errors.AiBomError) {
	jobID, err := c.createAIBOM(ctx, orgID, bundleHash)
	if err != nil {
		c.logger.Debug().Err(err.SnykError).Msg("error while creating the aibom")
		return "", err
	}

	progressBar := c.userInterface.NewProgressBar()
	progressBar.SetTitle("Analyzing")
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

	aiBomID, err := c.pollForAIBOMReady(ctx, orgID, jobID)
	if err != nil {
		c.logger.Debug().Err(err.SnykError).Msg("error while polling for the aibom")
		return "", err
	}

	aiBom, err := c.getAIBOM(ctx, orgID, aiBomID)
	if err != nil {
		c.logger.Debug().Err(err.SnykError).Msg("error while getting the aibom")
		return "", err
	}

	return aiBom, nil
}

func (c *AIBOMClientImpl) createAIBOM(
	ctx context.Context,
	orgID,
	bundleHash string,
) (string, *errors.AiBomError) {
	c.logger.Debug().Str("bundleHash", bundleHash).Msg("creating aibom")

	data := CreateAiBomRequestData{}
	err := data.FromFileBundleStoreData(FileBundleStoreData{
		Type: FileBundleStoreDataTypeAiBomFileBundle,
		Attributes: FileBundleStoreAttributes{
			BundleId: bundleHash,
		},
	})
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while creating FileBundleStoreData")
		return "", errors.NewInternalError(fmt.Sprintf("Error creating FileBundleStoreData: %s", err.Error()))
	}
	body := CreateAiBomRequestBody{Data: data}

	reqBytes, err := json.Marshal(body)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while marshaling request body")
		return "", errors.NewInternalError(fmt.Sprintf("Error marshaling request body: %s", err.Error()))
	}
	url := fmt.Sprintf("%s/rest/orgs/%s/ai_boms?version=%s", c.baseURL, orgID, APIVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(reqBytes))
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while building CreateAIBOM request")
		return "", errors.NewInternalError(fmt.Sprintf("Error building CreateAIBOM request: %s", err.Error()))
	}

	c.setCommonHeaders(url, req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Debug().Err(err).Msg("CreateAIBOM request HTTP error")
		if strings.Contains(strings.ToLower(err.Error()), "authentication") {
			return "", errors.NewUnauthorizedError("CreateAIBOM request failed with authentication error.")
		}
		return "", errors.NewInternalError(fmt.Sprintf("CreateAIBOM request HTTP error: %s", err.Error()))
	}

	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while reading CreateAIBOM response body")
		return "", errors.NewInternalError(fmt.Sprintf("Failed to read CreateAIBOM response body: %s", err.Error()))
	}

	if resp.StatusCode != http.StatusAccepted {
		errMsg := fmt.Sprintf(
			"expected status code %d but got %d for CreateAIBOM",
			http.StatusAccepted, resp.StatusCode)
		c.logger.Debug().Str(
			"responseBody",
			string(bodyBytes)).Msg(errMsg)
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return "", errors.NewUnauthorizedError(errMsg)
		case http.StatusForbidden:
			return "", errors.NewForbiddenError(errMsg)
		default:
			return "", errors.NewInternalError(errMsg)
		}
	}

	aiBomRespBody := CreateAiBomResponseBody{}
	err = json.Unmarshal(bodyBytes, &aiBomRespBody)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while unmarshaling CreateAiBomResponseBody")
		return "", errors.NewInternalError(fmt.Sprintf("Failed to unmarshal CreateAiBomResponseBody: %s", err.Error()))
	}

	aibomJobID := aiBomRespBody.Data.Id.String()
	c.logger.Debug().Str("aiBomJobId", aibomJobID).Msg("created ai bom")

	return aibomJobID, nil
}

func (c *AIBOMClientImpl) pollForAIBOMReady(
	ctx context.Context,
	orgID string,
	jobID string,
) (string, *errors.AiBomError) {
	url := fmt.Sprintf("%s/rest/orgs/%s/ai_bom_jobs/%s?version=%s", c.baseURL, orgID, jobID, APIVersion)
	numberOfPolls := 0

	for numberOfPolls <= maxPollAttempts {
		numberOfPolls++

		jobResp, err := c.fetchJobStatus(ctx, url)
		if err != nil {
			return "", err
		}

		result, shouldContinue, err := c.processJobResponse(jobResp)
		if err != nil {
			return "", err
		}
		if !shouldContinue {
			return result, nil
		}

		time.Sleep(pollInterval)
	}
	return "", errors.NewInternalError("AI-BOM polling timed out.")
}

func (c *AIBOMClientImpl) fetchJobStatus(
	ctx context.Context,
	url string,
) (*GetAiBomResponseJobBody, *errors.AiBomError) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while building GetAIBOMJob request")
		return nil, errors.NewInternalError(fmt.Sprintf("Error building GetAIBOMJob request: %s", err.Error()))
	}
	c.setCommonHeaders(url, req)
	req.Header.Set("Content-Type", "application/vnd.api+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Debug().Err(err).Msg("GetAIBOMJob request HTTP error")
		if strings.Contains(strings.ToLower(err.Error()), "authentication") {
			return nil, errors.NewUnauthorizedError("GetAIBOMJob request failed with authentication error.")
		}
		return nil, errors.NewInternalError(fmt.Sprintf("GetAIBOMJob request HTTP error: %s", err.Error()))
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while reading GetAIBOMJob response body")
		return nil, errors.NewInternalError(fmt.Sprintf("Failed to read GetAIBOMJob response body: %s", err.Error()))
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusSeeOther {
		return nil, c.handleJobStatusError(resp.StatusCode, bodyBytes)
	}

	var jobResp GetAiBomResponseJobBody
	err = json.Unmarshal(bodyBytes, &jobResp)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while unmarshaling GetAiBomResponseJobBody")
		return nil, errors.NewInternalError(fmt.Sprintf("Failed to unmarshal GetAiBomResponseJobBody: %s", err.Error()))
	}

	return &jobResp, nil
}

func (c *AIBOMClientImpl) handleJobStatusError(statusCode int, bodyBytes []byte) *errors.AiBomError {
	errMsg := fmt.Sprintf(
		"expected status code %d or %d but got %d for getAIBOMJob",
		http.StatusOK, http.StatusSeeOther, statusCode)
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

func (c *AIBOMClientImpl) processJobResponse(
	jobResp *GetAiBomResponseJobBody,
) (aiBomID string, shouldContinue bool, err *errors.AiBomError) {
	jobState := jobResp.Data.Attributes.Status
	c.logger.Debug().Str("jobStatus", string(jobState)).Msg("job status")

	switch jobState {
	case JobStateFinished:
		if jobResp.Data.Relationships == nil {
			return "", false, errors.NewInternalError("Finished ai_bom_job returned without relationships")
		}
		aiBomID = jobResp.Data.Relationships.AiBom.Data.Id.String()
		if aiBomID == "" {
			return "", false, errors.NewInternalError("Finished ai_bom_job returned without an ai_bom ID")
		}
		return aiBomID, false, nil
	case JobStateErrored:
		return "", false, errors.NewInternalError("Job is in errored state")
	case JobStateProcessing:
		return "", true, nil
	default:
		return "", false, errors.NewInternalError(fmt.Sprintf("Unexpected job state: %s", string(jobState)))
	}
}

func (c *AIBOMClientImpl) getAIBOM(
	ctx context.Context,
	orgID,
	aiBomID string,
) (string, *errors.AiBomError) {
	url := fmt.Sprintf("%s/rest/orgs/%s/ai_boms/%s?version=%s", c.baseURL, orgID, aiBomID, APIVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while building GetAIBOM request")
		return "", errors.NewInternalError(fmt.Sprintf("Error building GetAIBOM request: %s", err.Error()))
	}
	c.setCommonHeaders(url, req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Debug().Err(err).Msg("GetAIBOM request HTTP error")
		if strings.Contains(strings.ToLower(err.Error()), "authentication") {
			return "", errors.NewUnauthorizedError("GetAIBOM request failed with authentication error.")
		}
		return "", errors.NewInternalError(fmt.Sprintf("GetAIBOM request HTTP error: %s", err.Error()))
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while reading GetAIBOM response body")
		return "", errors.NewInternalError(fmt.Sprintf("Failed to read GetAIBOM response body: %s", err.Error()))
	}

	if resp.StatusCode != http.StatusOK {
		errMsg := fmt.Sprintf(
			"expected status code %d but got %d for getAIBOM",
			http.StatusOK, resp.StatusCode)
		c.logger.Debug().Str(
			"responseBody",
			string(bodyBytes)).Msg(errMsg)
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return "", errors.NewUnauthorizedError(errMsg)
		case http.StatusForbidden:
			return "", errors.NewForbiddenError(errMsg)
		default:
			return "", errors.NewInternalError(errMsg)
		}
	}

	aiBomJobRespBody := GetAiBomResponseBody{}
	err = json.Unmarshal(bodyBytes, &aiBomJobRespBody)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while unmarshaling GetAiBomResponseBody")
		return "", errors.NewInternalError(fmt.Sprintf("Failed to unmarshal GetAiBomResponseBody: %s", err.Error()))
	}

	attributesBytes, err := json.Marshal(aiBomJobRespBody.Data.Attributes)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error while marshaling attributes")
		return "", errors.NewInternalError(fmt.Sprintf("Failed to marshal attributes: %s", err.Error()))
	}
	aiBom := string(attributesBytes)

	c.logger.Debug().Str("aiBom", string(attributesBytes)).Msg("got ai-bom")

	return aiBom, nil
}

func (c *AIBOMClientImpl) setCommonHeaders(url string, req *http.Request) {
	requestID := uuid.New().String()
	c.logger.Debug().Msgf("making ai-bom api request to url: %s, requestId: %s", url, requestID)
	req.Header.Set("snyk-request-id", requestID)
	req.Header.Set("Authorization", "token "+c.authToken)
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Content-Type", "application/vnd.api+json")
}
