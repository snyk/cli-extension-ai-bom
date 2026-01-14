package aibomcreate

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-ai-bom/internal/errors"
	aiBomClient "github.com/snyk/cli-extension-ai-bom/internal/services/ai-bom-client"
	"github.com/snyk/cli-extension-ai-bom/internal/services/code"
	"github.com/snyk/cli-extension-ai-bom/internal/services/depgraph"

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
	codeService := code.NewCodeServiceImpl()
	depGraphService := depgraph.NewDepgraphServiceImpl()
	logger := invocationCtx.GetEnhancedLogger()
	ui := invocationCtx.GetUserInterface()
	config := invocationCtx.GetConfiguration()
	baseAPIURL := config.GetString(configuration.API_URL)
	aiBomClient := aiBomClient.NewAiBomClient(logger, invocationCtx.GetNetworkAccess().GetHttpClient(), ui, userAgent, baseAPIURL)
	return RunAiBomWorkflow(invocationCtx, codeService, depGraphService, aiBomClient)
}

//go:embed aibom.html
var htmlTemplate string

func RunAiBomWorkflow(
	invocationCtx workflow.InvocationContext,
	codeService code.CodeService,
	depgraphService depgraph.DepgraphService,
	aiBomClient aiBomClient.AiBomClient,
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
	orgID := config.GetString(configuration.ORGANIZATION)
	if orgID == "" {
		logger.Debug().Msg("no org id found")
		// This check captures unauthorized users that don't provide an explicit orgId.
		// Without this check the orgId would be empty and the api availability check would fail with 404.
		// Users that do provide an explicit orgId will be handled by the api availability check
		return nil, errors.NewUnauthorizedError("").SnykError
	}
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

	depGraphResult, err := depgraphService.GetDepgraph(invocationCtx)
	if err != nil {
		// We just log a warning here; no return as we want to still proceed even without depgraphs.
		logger.Warn().Msg("Failed to get the depgraph")
	} else {
		numGraphs := len(depGraphResult.DepgraphBytes)
		logger.Debug().Msgf("Generated %d depgraph(s)\n", numGraphs)
	}

	// transform a depGraphResult into a map[string][]byte
	depGraphMap := make(map[string][]byte)
	if depGraphResult != nil {
		for i, depGraph := range depGraphResult.DepgraphBytes {
			depGraphMap[fmt.Sprintf("%s_%d.snykdepgraph", path+"/", i)] = depGraph
		}
	}

	ui := invocationCtx.GetUserInterface()
	bundleHash, bundleErr := codeService.UploadBundle(path, depGraphMap,
		invocationCtx.GetNetworkAccess().GetHttpClient(), logger, config, ui)
	if bundleErr != nil {
		logger.Debug().Err(bundleErr.SnykError).Msg("error while uploading bundle")
		return nil, bundleErr.SnykError
	}

	var aiBomDoc string
	var createAIBomErr *errors.AiBomError

	if upload {
		aiBomDoc, createAIBomErr = aiBomClient.CreateAndUploadAIBOM(ctx, orgID, bundleHash, repoName)
	} else {
		aiBomDoc, createAIBomErr = aiBomClient.GenerateAIBOM(ctx, orgID, bundleHash)
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
