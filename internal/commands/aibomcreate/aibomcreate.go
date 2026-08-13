package aibomcreate

import (
	"bytes"
	"context"
	stdErrors "errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"text/template"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	frameworkUtils "github.com/snyk/go-application-framework/pkg/utils"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-secrets/pkg/filefilter"

	"github.com/snyk/cli-extension-ai-bom/internal/errors"
	aiBomClient "github.com/snyk/cli-extension-ai-bom/internal/services/ai-bom-client"

	"github.com/snyk/cli-extension-ai-bom/internal/utils"

	_ "embed"

	"github.com/spf13/pflag"
)

var (
	WorkflowID     = workflow.NewWorkflowIdentifier("aibom")
	WorkflowIDTest = workflow.NewWorkflowIdentifier("aibom.test")
)

func RegisterWorkflows(e workflow.Engine) error {
	flagset := pflag.NewFlagSet("snyk-cli-extension-ai-bom", pflag.ExitOnError)
	flagset.Bool(utils.FlagExperimental, false, "Deprecated: no longer required")
	flagset.Bool(utils.FlagHTML, false, "Output the AI BOM in HTML format instead of JSON")
	flagset.Bool(utils.FlagUpload, false, "Upload the AI BOM")
	flagset.Bool(utils.FlagEnriched, false, "Run additional slower enrichment on the AI-BOM")
	flagset.String(utils.FlagRepoName, "", "Repository name to use for the AI BOM")

	workflowConfiguration := workflow.ConfigurationOptionsFromFlagset(flagset)
	if _, err := e.Register(WorkflowID, workflowConfiguration, AiBomWorkflow); err != nil {
		return fmt.Errorf("error while registering AI-BOM workflow: %w", err)
	}
	if _, err := e.Register(WorkflowIDTest, workflowConfiguration, AiBomWorkflow); err != nil {
		return fmt.Errorf("error while registering AI-BOM test workflow: %w", err)
	}
	return nil
}

var userAgent = "cli-extension-ai-bom"

func AiBomWorkflow(invocationCtx workflow.InvocationContext, _ []workflow.Data) (output []workflow.Data, err error) {
	logger := invocationCtx.GetEnhancedLogger()
	ui := invocationCtx.GetUserInterface()
	config := invocationCtx.GetConfiguration()
	baseAPIURL := config.GetString(configuration.API_URL)
	client := aiBomClient.NewAiBomClient(logger, invocationCtx.GetNetworkAccess().GetHttpClient(), ui, userAgent, baseAPIURL)

	orgID := config.GetString(configuration.ORGANIZATION)
	if orgID == "" {
		logger.Debug().Msg("no org id found")
		// This check captures unauthorized users that don't provide an explicit orgId.
		// Without this check the orgId would be empty and the api availability check would fail with 404.
		// Users that do provide an explicit orgId will be handled by the api availability check
		return nil, errors.NewUnauthorizedError("").SnykError
	}

	orgIDUUID, err := uuid.Parse(orgID)
	if err != nil {
		logger.Debug().Err(err).Msg("error while parsing orgID")
		return nil, errors.NewInternalError("error while parsing orgID").SnykError
	}

	fileUploadClient := fileupload.NewClient(invocationCtx.GetNetworkAccess().GetHttpClient(), fileupload.Config{
		OrgID:   orgIDUUID,
		BaseURL: baseAPIURL,
	})

	cmdStr := workflow.GetCommandFromWorkflowIdentifier(invocationCtx.GetWorkflowIdentifier())
	runTest := cmdStr == "aibom test"

	return RunAiBomWorkflow(invocationCtx, orgIDUUID, client, fileUploadClient, runTest)
}

//go:embed aibom.html
var htmlTemplate string

//nolint:ireturn // workflow.Data is an interface from external library; cannot change return type
func rawJSONData(jsonOutput string) workflow.Data {
	return newWorkflowData("application/json", []byte(jsonOutput))
}

// runTestFlow runs the CLI policy test and returns workflow data (raw JSON or pretty output).
func runTestFlow(
	invocationCtx workflow.InvocationContext,
	logger *zerolog.Logger,
	client aiBomClient.AiBomClient,
	orgID uuid.UUID,
	aiBomID string,
	jsonOutput bool,
) ([]workflow.Data, error) {
	ctx := context.Background()
	logger.Debug().Str("aiBomID", aiBomID).Msg("Testing AI-BOM with CLI policy test")
	testResult, testErr := client.TestAIBOM(ctx, orgID, aiBomID)
	if testErr != nil {
		logger.Debug().Err(testErr.SnykError).Msg("error while testing AI-BOM")
		return nil, testErr.SnykError
	}
	logger.Debug().Msg("Successfully tested AI-BOM")
	parsed, parseErr := ParseTestResult(testResult)
	if parseErr != nil {
		logger.Debug().Err(parseErr).Msg("failed to parse test result, returning raw JSON")
		return nil, errors.NewInternalError("error while parsing AI-BOM test result").SnykError
	}
	config := invocationCtx.GetConfiguration()
	severityThreshold := strings.ToLower(config.GetString(configuration.FLAG_SEVERITY_THRESHOLD))
	filtered, filterErr := ApplySeverityThreshold(parsed, severityThreshold)
	if filterErr != nil {
		logger.Debug().Err(filterErr).Msg("failed to apply severity threshold to test result")
		return nil, errors.NewInternalError("error while filtering AI-BOM test result").SnykError
	}
	summaryData := workflow.NewData(
		workflow.NewTypeIdentifier(WorkflowIDTest, "test-summary"),
		content_type.TEST_SUMMARY,
		filtered.Summary,
	)
	dataToReturn := []workflow.Data{summaryData}
	if jsonOutput {
		logger.Debug().Msg("json output flag is set, skipping pretty output")
		filteredJSON, jsonFilterErr := FilterTestResultJSON(testResult, severityThreshold)
		if jsonFilterErr != nil {
			logger.Debug().Err(jsonFilterErr).Msg("failed to filter test result JSON by severity threshold")
			return nil, errors.NewInternalError("error while filtering AI-BOM test result").SnykError
		}
		return append(dataToReturn, rawJSONData(filteredJSON)), nil
	}
	var prettyBuf bytes.Buffer
	if err := RenderPrettyResult(invocationCtx, &prettyBuf, filtered); err != nil {
		logger.Debug().Err(err).Msg("failed to render test result, returning raw JSON")
		filteredJSON, jsonFilterErr := FilterTestResultJSON(testResult, severityThreshold)
		if jsonFilterErr != nil {
			logger.Debug().Err(jsonFilterErr).Msg("failed to filter test result JSON by severity threshold")
			return nil, errors.NewInternalError("error while filtering AI-BOM test result").SnykError
		}
		return append(dataToReturn, rawJSONData(filteredJSON)), nil
	}
	workflowData := newWorkflowData("text/plain", prettyBuf.Bytes())
	return append(dataToReturn, workflowData), nil
}

func RunAiBomWorkflow(
	invocationCtx workflow.InvocationContext,
	orgID uuid.UUID,
	client aiBomClient.AiBomClient,
	fileUploadClient fileupload.Client,
	runTest bool,
) ([]workflow.Data, error) {
	logger := invocationCtx.GetEnhancedLogger()
	config := invocationCtx.GetConfiguration()

	config.Set(configuration.RAW_CMD_ARGS, os.Args[1:])
	path := config.GetString(configuration.INPUT_DIRECTORY)
	upload := config.GetBool(utils.FlagUpload)
	enriched := config.GetBool(utils.FlagEnriched)
	repoName := config.GetString(utils.FlagRepoName)
	jsonOutput := config.GetString(utils.FlagJSONFileOutput) != ""

	ctx := context.Background()
	logger.Debug().Msgf("running command with orgId: %s", orgID)

	if upload && repoName == "" {
		logger.Debug().Msg("upload flag is set but repo name is not set")
		return nil, errors.NewInvalidArgumentError("repo name is required when monitor flag is set").SnykError
	}

	if runTest && upload {
		logger.Debug().Msg("test and upload flow is currently not supported")
		return nil, errors.NewInvalidArgumentError("test and upload flow is currently not supported").SnykError
	}

	logger.Debug().Msg("checking api availability")
	aiBomErr := client.CheckAPIAvailability(ctx, orgID)

	if aiBomErr != nil {
		logger.Debug().Msg("api availability check failed")
		return nil, aiBomErr.SnykError
	}

	logger.Debug().Msg("AI BOM workflow start")

	uploadRevisionID, err := filterAndUploadFiles(ctx, invocationCtx, fileUploadClient, logger, path)
	if err != nil {
		if stdErrors.Is(err, fileupload.ErrNoFilesProvided) {
			return nil, errors.NewNoSupportedFilesError().SnykError
		}

		logger.Error().Err(err).Msg("error while filtering and uploading files")
		return nil, err
	}

	var aiBomDoc string
	var aiBomID string
	var createAIBomErr *errors.AiBomError

	// All methods now return both document and ID
	if upload {
		aiBomDoc, aiBomID, createAIBomErr = client.CreateAndUploadAIBOM(ctx, orgID, uploadRevisionID, repoName, enriched)
	} else {
		aiBomDoc, aiBomID, createAIBomErr = client.GenerateAIBOM(ctx, orgID, uploadRevisionID, enriched)
	}

	if createAIBomErr != nil {
		logger.Debug().Err(createAIBomErr.SnykError).Msg("error while generating AI-BOM")
		return nil, createAIBomErr.SnykError
	}

	// If test subcommand was used, call the test endpoint
	if runTest {
		return runTestFlow(invocationCtx, logger, client, orgID, aiBomID, jsonOutput)
	}

	logger.Debug().Msg("Successfully generated AI BOM document.")

	workflowData := newWorkflowData("application/json", []byte(aiBomDoc))

	if config.GetBool(utils.FlagHTML) {
		html, err := generateHTML(aiBomDoc)
		if err != nil {
			logger.Debug().Err(err).Msg("error while generating HTML workflow data")
			return nil, err
		}

		workflowData = newWorkflowData("text/html", []byte(html))
	}

	return []workflow.Data{workflowData}, nil
}

func filterAndUploadFiles(
	ctx context.Context,
	invocationCtx workflow.InvocationContext,
	client fileupload.Client,
	logger *zerolog.Logger,
	inputPath string,
) (uuid.UUID, error) {
	filter := invocationCtx.GetFileFilter(inputPath, frameworkUtils.WithThreadNumber(runtime.NumCPU()))

	// The filefilter pipeline discovers .gitignore itself.
	rules, err := filter.GetRules([]string{".dcignore", ".snyk"})
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("failed to get file filter rules: %w", err)
	}

	textFilesFilter := filefilter.NewPipeline(
		filefilter.WithConcurrency(runtime.NumCPU()),
		// we only want to upload files that are not excluded by the rules
		filefilter.WithExcludeGlobs(rules),
		filefilter.WithFilters(
			// The file upload api only supports files up to 50mb
			filefilter.FileSizeFilter(logger),
			// we only want to upload text files
			filefilter.TextFileOnlyFilter(logger),
		),
		filefilter.WithLogger(logger),
		filefilter.WithInvocationContext(invocationCtx),
	)
	pathsChan := textFilesFilter.Filter(ctx, []string{inputPath})

	uploadRevision, err := client.CreateRevisionFromChan(ctx, pathsChan, inputPath)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("failed to create upload revision: %w", err)
	}

	return uploadRevision.RevisionID, nil
}

func generateHTML(aiBomDoc string) (string, error) {
	tmpl, err := template.New(WorkflowID.String()).Parse(htmlTemplate)
	if err != nil {
		return "", errors.NewInternalError("Error parsing HTML template.").SnykError
	}

	var html strings.Builder
	if err := tmpl.Execute(&html, aiBomDoc); err != nil {
		return "", errors.NewInternalError("Error executing HTML template.").SnykError
	}

	return html.String(), nil
}

//nolint:ireturn // Unable to change return type of external library
func newWorkflowData(contentType string, aisbom []byte) workflow.Data {
	return workflow.NewData(
		workflow.NewTypeIdentifier(WorkflowID, "aibom"),
		contentType,
		aisbom,
	)
}
