package aibomcreate

import (
	goErrors "errors"
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-ai-bom/internal/errors"
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

	configuration := workflow.ConfigurationOptionsFromFlagset(flagset)
	if _, err := e.Register(WorkflowID, configuration, AiBomWorkflow); err != nil {
		return fmt.Errorf("error while registering AI-BOM workflow: %w", err)
	}
	return nil
}

func AiBomWorkflow(invocationCtx workflow.InvocationContext, _ []workflow.Data) (output []workflow.Data, err error) {
	codeService := code.NewCodeServiceImpl()
	depGraphService := depgraph.NewDepgraphServiceImpl()
	return RunAiBomWorkflow(invocationCtx, codeService, depGraphService)
}

//go:embed aibom.html
var htmlTemplate string

func RunAiBomWorkflow(
	invocationCtx workflow.InvocationContext,
	codeService code.CodeService,
	depgraphService depgraph.DepgraphService,
) ([]workflow.Data, error) {
	logger := invocationCtx.GetEnhancedLogger()
	config := invocationCtx.GetConfiguration()

	config.Set(configuration.RAW_CMD_ARGS, os.Args[1:])
	experimental := config.GetBool(utils.FlagExperimental)
	path := config.GetString(configuration.INPUT_DIRECTORY)

	// As this is an experimental feature, we only want to continue if the experimental flag is set
	if !experimental {
		logger.Debug().Msg("Required experimental flag is not present")
		return nil, errors.NewCommandIsExperimentalError().SnykError
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

	response, resultMetaData, codeErr := codeService.Analyze(path, depGraphMap,
		invocationCtx.GetNetworkAccess().GetHttpClient, logger, config, invocationCtx.GetUserInterface())
	if codeErr != nil {
		logger.Debug().Err(codeErr.SnykError).Msg("error while analyzing code")
		return nil, codeErr.SnykError
	}
	logger.Debug().Msgf("Result metadata: %+v", resultMetaData)

	aiBomDoc, err := extractAiBomFromResult(response, logger)
	if err != nil {
		return nil, errors.NewInternalError(err.Error()).SnykError
	}

	logger.Debug().Msg("Successfully generated AI BOM document.")
	workflowData := newWorkflowData("application/json", []byte(aiBomDoc))

	if config.GetBool(utils.FlagHTML) {
		tmpl, err := template.New(WorkflowID.String()).Parse(htmlTemplate)
		if err != nil {
			logger.Debug().Err(err).Msg("error while parsing HTML template")
			return nil, errors.NewInternalError("Error parsing HTML template.").SnykError
		}

		var html strings.Builder
		if err := tmpl.Execute(&html, aiBomDoc); err != nil {
			logger.Debug().Err(err).Msg("error while executing HTML template")
			return nil, errors.NewInternalError("Error executing HTML template.").SnykError
		}

		workflowData = newWorkflowData("text/html", []byte(html.String()))
	}

	return []workflow.Data{workflowData}, nil
}

func extractAiBomFromResult(response *code.AnalysisResponse, logger *zerolog.Logger) (output string, err error) {
	if len(response.Sarif.Runs) != 1 {
		logger.Debug().Msgf("Failed to extract AI-BOM from result, %d runs in result, expected 1", len(response.Sarif.Runs))
		return "", goErrors.New("Failed to extract AI-BOM from result.")
	}
	var aiBomResults []code.SarifResult
	for _, result := range response.Sarif.Runs[0].Results {
		if strings.Contains(result.Message.Text, "bomFormat") {
			aiBomResults = append(aiBomResults, result)
		} else {
			logger.Warn().Msgf("unexpected result level: %s, ruleId: %s, message: %s", result.Level, result.RuleID, result.Message.Text)
		}
	}
	if len(aiBomResults) != 1 {
		logger.Debug().Msgf("Failed to extract AI-BOM from result, %d results in Runs[0], expected 1", len(aiBomResults))
		return "", goErrors.New("Failed to extract AI-BOM from result.")
	}
	return aiBomResults[0].Message.Text, nil
}

//nolint:ireturn // Unable to change return type of external library
func newWorkflowData(contentType string, aisbom []byte) workflow.Data {
	return workflow.NewData(
		workflow.NewTypeIdentifier(WorkflowID, "aibom"),
		contentType,
		aisbom,
	)
}
