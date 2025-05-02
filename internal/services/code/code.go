package code

//go:generate mockgen -package mock -destination mock/code_mock.go github.com/snyk/cli-extension-ai-bom/internal/services/code CodeService

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/rs/zerolog"
	codeclient "github.com/snyk/code-client-go"
	codeclienthttp "github.com/snyk/code-client-go/http"
	"github.com/snyk/code-client-go/scan"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/ui"
	frameworkUtils "github.com/snyk/go-application-framework/pkg/utils"

	"github.com/snyk/cli-extension-ai-bom/internal/utils"
)

//revive:disable:exported // The interface must be called CodeService to standardize.
type CodeService interface {
	Analyze(
		path string,
		httpClientFunc func() *http.Client,
		logger *zerolog.Logger,
		config configuration.Configuration,
		userInterface ui.UserInterface,
	) (*AnalysisResponse, *scan.ResultMetaData, error)
}

// CodeServiceImpl is an implementation of our CodeService using open telemetry.
type CodeServiceImpl struct {
	baseURL          string
	pollInterval     time.Duration
	maxNumberOfPolls int
}

var _ CodeService = (*CodeServiceImpl)(nil) // Assert that CodeServiceImpl implements CodeService

func NewCodeServiceImpl() *CodeServiceImpl {
	return &CodeServiceImpl{
		baseURL:          "http://localhost:9999",
		pollInterval:     500 * time.Millisecond,
		maxNumberOfPolls: 7200,
	}
}

const (
	ConfigurationTestFLowName = "internal_code_test_flow_name"
	AnalysisStatusComplete    = "COMPLETE"
	AnalysisStatusNotStarted  = "NOT_STARTED"
)

func (cs *CodeServiceImpl) Analyze(
	path string,
	httpClientFunc func() *http.Client,
	logger *zerolog.Logger,
	config configuration.Configuration,
	userInterface ui.UserInterface,
) (*AnalysisResponse, *scan.ResultMetaData, error) {
	var resultMetaData *scan.ResultMetaData
	httpClient := codeclienthttp.NewHTTPClient(
		httpClientFunc,
		codeclienthttp.WithLogger(logger),
	)
	requestID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, nil, fmt.Errorf("error generating uuid: %w", err)
	}
	logger.Debug().Msgf("Request ID: %s", requestID)

	bundleHash, err := uploadBundle(requestID, path, httpClient, logger, config, userInterface)
	if err != nil || bundleHash == "" {
		logger.Debug().Msg("failed to upload file bundle")
		return nil, nil, err
	}
	logger.Debug().Msg("successfully uploaded file bundle")

	postData, err := createPostData(bundleHash)
	if err != nil {
		return nil, nil, err
	}

	progressBar := userInterface.NewProgressBar()
	progressBar.SetTitle("Analyzing")
	err = progressBar.UpdateProgress(ui.InfiniteProgress)
	if err != nil {
		logger.Debug().Msg("failed to update progress bar")
	}
	defer func() {
		err = progressBar.Clear()
		if err != nil {
			logger.Debug().Msg("failed to clear progress bar")
		}
	}()

	// Poll until analysis status is failed or complete
	analysisResp := AnalysisResponse{Status: AnalysisStatusNotStarted}
	postURL := fmt.Sprintf("%s/analysis", SnykCodeAPI(config))
	numberOfPolls := 0
	ctx := context.Background()
	for numberOfPolls <= cs.maxNumberOfPolls {
		numberOfPolls++
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, postURL, bytes.NewBuffer(postData))
		if err != nil {
			return nil, nil, fmt.Errorf("error building analysis request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		res, err := httpClient.Do(req)
		if res.StatusCode != http.StatusOK {
			return nil, nil, fmt.Errorf("analysis request failed with status code %d", res.StatusCode)
		}

		analysisResp, err = buildAnalysisResponse(res, err)
		if err != nil {
			logger.Debug().Msg("error in handleResponse for analysis")
			return nil, nil, err
		}
		if analysisResp.Status == AnalysisStatusComplete {
			logger.Debug().Msg(fmt.Sprintf("analysis status: %s, SARIF received", analysisResp.Status))
			return &analysisResp, resultMetaData, nil
		}
		time.Sleep(cs.pollInterval)
	}

	logger.Debug().Msg("analysis polling timed out")
	return nil, nil, errors.New("analysis polling timed out")
}

func uploadBundle(requestID,
	path string,
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
		return "", fmt.Errorf("failed to upload bundle: %w", err)
	}
	return bundle.GetBundleHash(), nil
}

func SnykCodeAPI(config configuration.Configuration) string {
	if url := config.GetString(utils.ConfigurationSnykCodeAPIURL); url != "" {
		return url
	}
	return strings.ReplaceAll(config.GetString(configuration.API_URL), "api", "deeproxy")
}

//nolint:ireturn // ignored.
func getAnalysisInput(path string, config configuration.Configuration, logger *zerolog.Logger) (scan.Target, <-chan string, error) {
	var files <-chan string

	if fileinfo, fileInfoErr := os.Stat(path); fileInfoErr != nil || !fileinfo.IsDir() {
		return nil, nil, errors.New("only analysis of local file paths is supported")
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
		return nil, fmt.Errorf("failed to get file filter rules: %w", err)
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

func buildAnalysisResponse(res *http.Response, err error) (AnalysisResponse, error) {
	var analysisResponse AnalysisResponse
	if err != nil {
		return analysisResponse, fmt.Errorf("error making request: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return analysisResponse, fmt.Errorf("error reading response body: %w", err)
	}

	err = json.Unmarshal(body, &analysisResponse)
	if err != nil {
		return analysisResponse, fmt.Errorf("error unmarshaling response body: %w", err)
	}

	return analysisResponse, nil
}
