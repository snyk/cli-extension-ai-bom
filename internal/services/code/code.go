package code

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/rs/zerolog"
	codeclient "github.com/snyk/code-client-go"
	codebundle "github.com/snyk/code-client-go/bundle"
	codeclienthttp "github.com/snyk/code-client-go/http"
	"github.com/snyk/code-client-go/scan"

	errors "github.com/snyk/cli-extension-ai-bom/internal/errors"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/ui"
	frameworkUtils "github.com/snyk/go-application-framework/pkg/utils"

	"github.com/snyk/cli-extension-ai-bom/internal/utils"
)

//revive:disable:exported // The interface must be called CodeService to standardize.
type CodeService interface {
	Analyze(
		path string,
		depgraph map[string][]byte,
		httpClientFunc func() *http.Client,
		logger *zerolog.Logger,
		config configuration.Configuration,
		userInterface ui.UserInterface,
	) (*AnalysisResponse, *scan.ResultMetaData, *errors.AiBomError)
}

// CodeServiceImpl is an implementation of our CodeService using open telemetry.
type CodeServiceImpl struct {
	pollInterval     time.Duration
	maxNumberOfPolls int
}

var _ CodeService = (*CodeServiceImpl)(nil) // Assert that CodeServiceImpl implements CodeService

func NewCodeServiceImpl() *CodeServiceImpl {
	return &CodeServiceImpl{
		pollInterval:     500 * time.Millisecond,
		maxNumberOfPolls: 7200,
	}
}

const (
	ConfigurationTestFLowName = "internal_code_test_flow_name"
	AnalysisStatusComplete    = "COMPLETE"
	AnalysisStatusAnalyzing   = "ANALYZING"
	AnalysisStatusProgress    = "PROGRESS"
	AnalysisStatusWaiting     = "WAITING"
	AnalysisStatusNotStarted  = "NOT_STARTED"
)

func (cs *CodeServiceImpl) Analyze(
	path string,
	depgraphs map[string][]byte,
	httpClientFunc func() *http.Client,
	logger *zerolog.Logger,
	config configuration.Configuration,
	userInterface ui.UserInterface,
) (*AnalysisResponse, *scan.ResultMetaData, *errors.AiBomError) {
	httpClient := codeclienthttp.NewHTTPClient(
		httpClientFunc,
		codeclienthttp.WithLogger(logger),
	)
	requestID, err := uuid.GenerateUUID()
	if err != nil {
		logger.Debug().Err(err).Msg("error generating requestID")
		return nil, nil, errors.NewInternalError("Error generating requestID.")
	}
	logger.Debug().Msgf("Request ID: %s", requestID)
	bundleHash, err := uploadBundle(requestID, path, depgraphs, httpClient, logger, config, userInterface)
	if err != nil {
		logger.Debug().Err(err).Msg("error while uploading file bundle")
		if strings.Contains(strings.ToLower(err.Error()), "authentication") {
			return nil, nil, errors.NewUnauthorizedError("Upload failed with authentication error.")
		}
		if strings.Contains(strings.ToLower(err.Error()), "no files to scan") {
			return nil, nil, errors.NewNoSupportedFilesError()
		}
		return nil, nil, errors.NewInternalError(err.Error())
	}
	if bundleHash == "" {
		logger.Debug().Msg("empty bundle hash to upload file bundle")
		return nil, nil, errors.NewNoSupportedFilesError()
	}
	logger.Debug().Msg("successfully uploaded file bundle")

	progressBar := userInterface.NewProgressBar()
	progressBar.SetTitle("Analyzing")
	err = progressBar.UpdateProgress(ui.InfiniteProgress)
	if err != nil {
		logger.Debug().Err(err).Msg("Failed to update progress bar")
	}
	defer func() {
		err = progressBar.Clear()
		if err != nil {
			logger.Debug().Err(err).Msg("Failed to clear progress bar")
		}
	}()

	return cs.pollForAnalysis(bundleHash, httpClient, logger, config)
}

func (cs *CodeServiceImpl) pollForAnalysis(
	bundleHash string,
	httpClient codeclienthttp.HTTPClient,
	logger *zerolog.Logger,
	config configuration.Configuration,
) (*AnalysisResponse, *scan.ResultMetaData, *errors.AiBomError) {
	postData, err := createPostData(bundleHash)
	if err != nil {
		logger.Debug().Err(err).Msg("error while creating post data")
		return nil, nil, errors.NewInternalError(fmt.Sprintf("Error creating analysis post request: %s.", err.Error()))
	}

	var resultMetaData *scan.ResultMetaData

	// Poll until analysis status is failed or complete
	analysisResp := AnalysisResponse{Status: AnalysisStatusNotStarted}
	postURL := fmt.Sprintf("%s/analysis", SnykCodeAPI(config))
	numberOfPolls := 0
	ctx := context.Background()

	healthyStatus := map[string]struct{}{
		AnalysisStatusComplete:  {},
		AnalysisStatusProgress:  {},
		AnalysisStatusWaiting:   {},
		AnalysisStatusAnalyzing: {},
	}

	for numberOfPolls <= cs.maxNumberOfPolls {
		numberOfPolls++
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, postURL, bytes.NewBuffer(postData))
		if err != nil {
			logger.Debug().Err(err).Msg("error while building analysis request")
			return nil, nil, errors.NewInternalError("Error building analysis request.")
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("snyk-org-name", config.GetString(configuration.ORGANIZATION))
		res, err := httpClient.Do(req)
		if err != nil {
			logger.Debug().Err(err).Msg("analysis request HTTP error")
			return nil, nil, errors.NewInternalError("Analysis request HTTP error.")
		}
		if res == nil {
			logger.Debug().Err(err).Msg("analysis request failed with nil response")
			return nil, nil, errors.NewInternalError("Analysis request returned unexpected response.")
		}
		if res.StatusCode != http.StatusOK {
			failureMsg := fmt.Sprintf("Analysis request failed with status code %d.", res.StatusCode)
			logger.Debug().Msg(failureMsg)
			switch res.StatusCode {
			case http.StatusUnauthorized:
				return nil, nil, errors.NewUnauthorizedError(failureMsg)
			case http.StatusForbidden:
				return nil, nil, errors.NewForbiddenError(failureMsg)
			default:
				return nil, nil, errors.NewInternalError(fmt.Sprintf("Analysis request failed with status code %d.", res.StatusCode))
			}
		}

		analysisResp, err = buildAnalysisResponse(res)
		if err != nil {
			logger.Debug().Err(err).Msg("error while building response for analysis")
			return nil, nil, errors.NewInternalError("Error while building response for analysis.")
		}
		logger.Debug().Msg(fmt.Sprintf("analysis status: %s, SARIF received", analysisResp.Status))
		if _, found := healthyStatus[analysisResp.Status]; !found {
			return nil, nil, errors.NewInternalError(fmt.Sprintf("Analysis has completed with status: %s.", analysisResp.Status))
		}
		if analysisResp.Status == AnalysisStatusComplete {
			logger.Debug().Msg("analysis is complete")
			return &analysisResp, resultMetaData, nil
		}
		time.Sleep(cs.pollInterval)
	}

	logger.Debug().Msg("analysis polling timed out")
	return nil, nil, errors.NewInternalError("Analysis polling timed out.")
}

func uploadBundle(requestID,
	path string,
	depgraphs map[string][]byte,
	httpClient codeclienthttp.HTTPClient,
	logger *zerolog.Logger,
	config configuration.Configuration,
	userInterface ui.UserInterface,
) (string, error) {
	ctx := context.Background()

	progressFactory := ProgressTrackerFactory{
		userInterface: userInterface,
		logger:        logger,
	}

	codeScannerConfig := &codeClientConfig{
		localConfiguration: config,
	}

	codeScannerOptions := []codeclient.OptionFunc{
		codeclient.WithLogger(logger),
		codeclient.WithTrackerFactory(progressFactory),
		codeclient.WithFlow(config.GetString(ConfigurationTestFLowName)),
	}

	codeScanner := codeclient.NewCodeScanner(
		codeScannerConfig,
		httpClient,
		codeScannerOptions...,
	)

	target, files, err := getAnalysisInput(path, config, logger)
	if err != nil {
		return "", err
	}

	logger.Debug().Msgf("Path: %s", path)
	logger.Debug().Msgf("Target: %s", target)

	changedFiles := make(map[string]bool)
	bundle, err := codeScanner.Upload(ctx, requestID, target, files, changedFiles)
	if err != nil {
		return "", fmt.Errorf("Failed to upload bundle: %w.", err)
	}

	// extend the bundle with the depgraphs
	if depgraphs != nil {
		depgraphBatch, err := codebundle.NewBatchFromRawContent(depgraphs)
		if err != nil {
			return "", fmt.Errorf("Failed to create depgraph batch: %w", err)
		}
		err = bundle.UploadBatch(ctx, requestID, depgraphBatch)
		if err != nil {
			return "", fmt.Errorf("Failed to update bundle with depgraphs: %w", err)
		}
	}

	return bundle.GetBundleHash(), nil
}

func SnykCodeAPI(config configuration.Configuration) string {
	if url := config.GetString(utils.ConfigurationSnykCodeClientProxyURL); url != "" {
		return url
	}
	return strings.ReplaceAll(config.GetString(configuration.API_URL), "api", "deeproxy")
}

//nolint:ireturn // ignored.
func getAnalysisInput(path string, config configuration.Configuration, logger *zerolog.Logger) (scan.Target, <-chan string, error) {
	var files <-chan string

	if fileinfo, fileInfoErr := os.Stat(path); fileInfoErr != nil || !fileinfo.IsDir() {
		return nil, nil, fmt.Errorf("only analysis of local file paths is supported. file path: %s", path)
	}

	target, err := scan.NewRepositoryTarget(path)
	if err != nil {
		logger.Warn().Err(err)
	}

	files, err = getFilesForPath(path, logger, config.GetInt(configuration.MAX_THREADS))
	if err != nil {
		return nil, nil, err
	}

	return target, files, nil
}

func getFilesForPath(path string, logger *zerolog.Logger, maxThreads int) (<-chan string, error) {
	filter := frameworkUtils.NewFileFilter(path, logger, frameworkUtils.WithThreadNumber(maxThreads))

	rules, err := filter.GetRules([]string{".gitignore", ".dcignore", ".snyk"})
	if err != nil {
		return nil, fmt.Errorf("Failed to get file filter rules: %w", err)
	}

	results := filter.GetFilteredFiles(filter.GetAllFiles(), rules)
	return results, nil
}

type KeyData struct {
	Type  string `json:"type"`
	Hash  string `json:"hash"`
	AiBom bool   `json:"aiBom"`
}

func createKeyData(bundleHash string) KeyData {
	return KeyData{
		Type:  "file",
		Hash:  bundleHash,
		AiBom: true,
	}
}

type PostData struct {
	Key KeyData `json:"key"`
}

func createPostData(bundleHash string) ([]byte, error) {
	postData := PostData{
		Key: createKeyData(bundleHash),
	}

	jsonData, err := json.Marshal(postData)
	if err != nil {
		return nil, fmt.Errorf("error marshaling JSON: %w", err)
	}

	return jsonData, nil
}

type AnalysisResponse struct {
	Status string `json:"status"`
	Sarif  Sarif  `json:"sarif"`
	// Other fields can be added here without breaking the code
	// due to the non-strict unmarshaling.
}

func buildAnalysisResponse(res *http.Response) (AnalysisResponse, error) {
	var analysisResponse AnalysisResponse
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return analysisResponse, fmt.Errorf("Error reading response body: %w.", err)
	}

	err = json.Unmarshal(body, &analysisResponse)
	if err != nil {
		return analysisResponse, fmt.Errorf("Error unmarshaling response body: %w.", err)
	}

	return analysisResponse, nil
}
