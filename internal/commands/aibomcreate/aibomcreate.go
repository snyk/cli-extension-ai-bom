package aibomcreate

import (
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
	frameworkUtils "github.com/snyk/go-application-framework/pkg/utils"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-secrets/pkg/filefilter"

	"github.com/snyk/cli-extension-ai-bom/internal/errors"
	aiBomClient "github.com/snyk/cli-extension-ai-bom/internal/services/ai-bom-client"

	"github.com/snyk/cli-extension-ai-bom/internal/utils"

	_ "embed"

	"github.com/spf13/pflag"
)

var WorkflowID = workflow.NewWorkflowIdentifier("aibom")

func RegisterWorkflows(e workflow.Engine) error {
	flagset := pflag.NewFlagSet("snyk-cli-extension-ai-bom", pflag.ExitOnError)
	flagset.Bool(utils.FlagExperimental, false, "This is an experiment feature that will contain breaking changes in future revisions")
	flagset.Bool(utils.FlagHTML, false, "Output the AI BOM in HTML format instead of JSON")
	flagset.Bool(utils.FlagUpload, false, "Upload the AI BOM")
	flagset.String(utils.FlagRepoName, "", "Repository name to use for the AI BOM")

	configuration := workflow.ConfigurationOptionsFromFlagset(flagset)
	if _, err := e.Register(WorkflowID, configuration, AiBomWorkflow); err != nil {
		return fmt.Errorf("error while registering AI-BOM workflow: %w", err)
	}
	return nil
}

var userAgent = "cli-extension-ai-bom"

func AiBomWorkflow(invocationCtx workflow.InvocationContext, _ []workflow.Data) (output []workflow.Data, err error) {
	logger := invocationCtx.GetEnhancedLogger()
	ui := invocationCtx.GetUserInterface()
	config := invocationCtx.GetConfiguration()
	baseAPIURL := config.GetString(configuration.API_URL)
	aiBomClient := aiBomClient.NewAiBomClient(logger, invocationCtx.GetNetworkAccess().GetHttpClient(), ui, userAgent, baseAPIURL)

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

	return RunAiBomWorkflow(invocationCtx, orgIDUUID, aiBomClient, fileUploadClient)
}

//go:embed aibom.html
var htmlTemplate string

func RunAiBomWorkflow(
	invocationCtx workflow.InvocationContext,
	orgID uuid.UUID,
	aiBomClient aiBomClient.AiBomClient,
	fileUploadClient fileupload.Client,
) ([]workflow.Data, error) {
	logger := invocationCtx.GetEnhancedLogger()
	config := invocationCtx.GetConfiguration()

	config.Set(configuration.RAW_CMD_ARGS, os.Args[1:])
	experimental := config.GetBool(utils.FlagExperimental)
	path := config.GetString(configuration.INPUT_DIRECTORY)
	upload := config.GetBool(utils.FlagUpload)
	repoName := config.GetString(utils.FlagRepoName)

	// As this is an experimental feature, we only want to continue if the experimental flag is set
	if !experimental {
		logger.Debug().Msg("Required experimental flag is not present")
		return nil, errors.NewCommandIsExperimentalError().SnykError
	}

	ctx := context.Background()
	logger.Debug().Msgf("running command with orgId: %s", orgID)

	if upload && repoName == "" {
		logger.Debug().Msg("upload flag is set but repo name is not set")
		return nil, errors.NewInvalidArgumentError("repo name is required when monitor flag is set").SnykError
	}

	logger.Debug().Msg("checking api availability")
	aiBomErr := aiBomClient.CheckAPIAvailability(ctx, orgID)

	if aiBomErr != nil {
		logger.Debug().Msg("api availability check failed")
		return nil, aiBomErr.SnykError
	}

	logger.Debug().Msg("AI BOM workflow start")

	uploadRevisionID, err := filterAndUploadFiles(ctx, fileUploadClient, logger, path)
	if err != nil {
		if stdErrors.Is(err, fileupload.ErrNoFilesProvided) {
			return nil, errors.NewNoSupportedFilesError().SnykError
		}

		logger.Error().Err(err).Msg("error while filtering and uploading files")
		return nil, err
	}

	var aiBomDoc string
	var createAIBomErr *errors.AiBomError

	if upload {
		aiBomDoc, createAIBomErr = aiBomClient.CreateAndUploadAIBOM(ctx, orgID, uploadRevisionID, repoName)
	} else {
		aiBomDoc, createAIBomErr = aiBomClient.GenerateAIBOM(ctx, orgID, uploadRevisionID)
	}

	if createAIBomErr != nil {
		logger.Debug().Err(createAIBomErr.SnykError).Msg("error while generating AI-BOM")
		return nil, createAIBomErr.SnykError
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

func filterAndUploadFiles(ctx context.Context, client fileupload.Client, logger *zerolog.Logger, inputPath string) (uuid.UUID, error) {
	filter := frameworkUtils.NewFileFilter(inputPath, logger, frameworkUtils.WithThreadNumber(runtime.NumCPU()))

	rules, err := filter.GetRules([]string{".gitignore", ".dcignore", ".snyk"})
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
