package code

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	codeclient "github.com/snyk/code-client-go"
	codebundle "github.com/snyk/code-client-go/bundle"
	codeclienthttp "github.com/snyk/code-client-go/http"
	"github.com/snyk/code-client-go/scan"

	errors "github.com/snyk/cli-extension-ai-bom/internal/errors"

	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/ui"
	frameworkUtils "github.com/snyk/go-application-framework/pkg/utils"

	"github.com/snyk/cli-extension-ai-bom/internal/utils"
)

//revive:disable:exported // The interface must be called CodeService to standardize.
type CodeService interface {
	UploadBundle(
		path string,
		depgraphs map[string][]byte,
		httpClient codeclienthttp.HTTPClient,
		logger *zerolog.Logger,
		config configuration.Configuration,
		userInterface ui.UserInterface,
	) (string, *errors.AiBomError)
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
	AnalysisStatusFetching    = "FETCHING"
	AnalysisStatusParsing     = "PARSING"
	AnalysisStatusStarting    = "STARTING"
	AnalysisStatusWaiting     = "WAITING"
	AnalysisStatusNotStarted  = "NOT_STARTED"
)

func (cs *CodeServiceImpl) UploadBundle(
	path string,
	depgraphs map[string][]byte,
	httpClient codeclienthttp.HTTPClient,
	logger *zerolog.Logger,
	config configuration.Configuration,
	userInterface ui.UserInterface,
) (string, *errors.AiBomError) {
	bundleHash, err := uploadBundle(path, depgraphs, httpClient, logger, config, userInterface)
	if err != nil {
		logger.Debug().Err(err).Msg("error while uploading file bundle")
		if strings.Contains(strings.ToLower(err.Error()), "authentication") {
			return "", errors.NewUnauthorizedError("Upload failed with authentication error.")
		}
		if strings.Contains(strings.ToLower(err.Error()), "no files to scan") {
			return "", errors.NewNoSupportedFilesError()
		}
		return "", errors.NewInternalError(err.Error())
	}
	if bundleHash == "" {
		logger.Debug().Msg("empty bundle hash to upload file bundle")
		return "", errors.NewNoSupportedFilesError()
	}
	logger.Debug().Msg("successfully uploaded file bundle")
	return bundleHash, nil
}

func uploadBundle(
	path string,
	depgraphs map[string][]byte,
	httpClient codeclienthttp.HTTPClient,
	logger *zerolog.Logger,
	config configuration.Configuration,
	userInterface ui.UserInterface,
) (string, error) {
	requestID := uuid.NewString()
	logger.Debug().Msgf("Request ID: %s", requestID)
	ctx := context.Background()

	progressFactory := ProgressTrackerFactory{
		userInterface: userInterface,
		logger:        logger,
	}

	target, files, err := getAnalysisInput(path, config, logger)
	if err != nil {
		return "", err
	}

	// TODO: feed through the correct http client
	fileuploadClient := fileupload.NewClient(&http.Client{}, fileupload.Config{},
		fileupload.WithLogger(logger),
	)

	uploadResult, err := fileuploadClient.CreateRevisionFromChan(ctx, files, path)
	if err != nil {
		return "", err
	}

	return uploadResult.RevisionID.String(), nil

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

	bundleHash := bundle.GetBundleHash()

	logger.Debug().Msgf("BundleHash: %s", bundleHash)
	return bundleHash, nil
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
