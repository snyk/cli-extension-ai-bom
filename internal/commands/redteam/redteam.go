package redteam

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	cli_errors "github.com/snyk/error-catalog-golang-public/cli"
	snyk_common_errors "github.com/snyk/error-catalog-golang-public/snyk"

	"github.com/snyk/cli-extension-ai-bom/internal/errors"
	redteamclient "github.com/snyk/cli-extension-ai-bom/internal/services/red-team-client"
	"github.com/snyk/cli-extension-ai-bom/internal/utils"

	_ "embed"

	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"

	"github.com/go-playground/validator/v10"
)

var WorkflowID = workflow.NewWorkflowIdentifier("redteam")

func RegisterWorkflows(e workflow.Engine) error {
	flagset := pflag.NewFlagSet("snyk-cli-extension-ai-bom-redteam", pflag.ExitOnError)
	flagset.Bool(utils.FlagExperimental, false, "This is an experiment feature that will contain breaking changes in future revisions")
	flagset.String(utils.FlagConfig, "redteam.yaml", "Path to the red team configuration file")

	configuration := workflow.ConfigurationOptionsFromFlagset(flagset)
	if _, err := e.Register(WorkflowID, configuration, Workflow); err != nil {
		return fmt.Errorf("error while registering red team workflow: %w", err)
	}
	return nil
}

var userAgent = "cli-extension-ai-bom-redteam"

func Workflow(invocationCtx workflow.InvocationContext, _ []workflow.Data) (output []workflow.Data, err error) {
	logger := invocationCtx.GetEnhancedLogger()
	ui := invocationCtx.GetUserInterface()
	config := invocationCtx.GetConfiguration()
	baseAPIURL := config.GetString(configuration.API_URL)
	redTeamClient := redteamclient.NewRedTeamClient(logger, invocationCtx.GetNetworkAccess().GetHttpClient(), ui, userAgent, baseAPIURL)
	return RunRedTeamWorkflow(invocationCtx, redTeamClient)
}

func RunRedTeamWorkflow(
	invocationCtx workflow.InvocationContext,
	redTeamClient redteamclient.RedTeamClient,
) ([]workflow.Data, error) {
	logger := invocationCtx.GetEnhancedLogger()
	config := invocationCtx.GetConfiguration()

	config.Set(configuration.RAW_CMD_ARGS, os.Args[1:])

	experimental := config.GetBool(utils.FlagExperimental)

	if !experimental {
		logger.Debug().Msg("Required experimental flag is not present")
		return nil, cli_errors.NewCommandIsExperimentalError("")
	}

	orgID := config.GetString(configuration.ORGANIZATION)
	if orgID == "" {
		logger.Debug().Msg("No organization id is found.")
		// This shouldn't really happen unless customer has explicitly unset the orgId.
		return nil, snyk_common_errors.NewUnauthorisedError("")
	}

	return handleRunScanCommand(invocationCtx, redTeamClient)
}

func handleRunScanCommand(invocationCtx workflow.InvocationContext, redTeamClient redteamclient.RedTeamClient) ([]workflow.Data, error) {
	logger := invocationCtx.GetEnhancedLogger()
	config := invocationCtx.GetConfiguration()
	ctx := context.Background()

	orgID := config.GetString(configuration.ORGANIZATION)

	configPath := config.GetString(utils.FlagConfig)
	if configPath == "" {
		logger.Debug().Msg("No config path provided, using default value.")
		configPath = "redteam.yaml"
	}

	// Check if config file exists
	if _, configFileErr := os.Stat(configPath); os.IsNotExist(configFileErr) {
		// TODO(pkey): move to GitBook docs
		message := `
Configuration file not found. Please create either a redteam.yaml file in the current directory
 or use the --config flag to specify a custom path. Example configuration:

target:
  name: <required, name your target> // Can be anything you want
  type: <required, e.g., api or socket_io> // The type of target to scan
  context:
    purpose: '<describe the use-case or intent>' // The use case for the app. The more information you provide, the better the scan will be.
  settings:
    url: '<required, e.g., https://vulnerable-app.com/chat/completions>' // The URL to scan
    headers: // Optional.
    - name: '<optional, e.g. Authorization>' // Authentication header.
      value: '<optional, e.g. Bearer TOKEN>' // Authentication header.
    response_selector: '<required, e.g., response>' // The path to the response in the JSON response payload
    request_body_template: '<required, e.g., {"message": "{{prompt}}"}>' // The request body template to use for the scan
options:
  vuln_definitions:
    exclude: []

For more details, refer to the documentation.
		`
		return []workflow.Data{newWorkflowData("text/plain", []byte(message))}, nil
	}

	configData, configErr := os.ReadFile(configPath)
	if configErr != nil {
		logger.Debug().Err(configErr).Msg("error while reading config file")
		return nil, errors.NewInternalError("Error reading configuration file").SnykError
	}

	var redTeamConfig redteamclient.RedTeamConfig

	yamlErr := yaml.Unmarshal(configData, &redTeamConfig)
	if yamlErr != nil {
		logger.Debug().Err(yamlErr).Msg("error while unmarshaling config")
		return nil, snyk_common_errors.NewServerError("Error parsing configuration file")
	}

	validate := validator.New()

	clientConfigErr := validate.Struct(redTeamConfig)

	if clientConfigErr != nil {
		return nil, cli_errors.NewValidationFailureError(clientConfigErr.Error())
	}

	clientConfig := redteamclient.RedTeamConfig{
		Target: redteamclient.AIScanTarget{
			Name:     redTeamConfig.Target.Name,
			Type:     redTeamConfig.Target.Type,
			Context:  redTeamConfig.Target.Context,
			Settings: redTeamConfig.Target.Settings,
		},
		Options: redteamclient.AIScanOptions{
			VulnDefinitions: redTeamConfig.Options.VulnDefinitions,
		},
	}

	logger.Debug().Msg("Starting red team scan")

	scanID, scanErr := redTeamClient.RunScan(ctx, orgID, &clientConfig)

	if scanErr != nil {
		return nil, fmt.Errorf("failed to create scan: %w", scanErr)
	}

	logger.Info().Msgf("Red team scan started with ID: %s", scanID)

	results, resultsErr := redTeamClient.GetScanResults(ctx, orgID, scanID)
	logger.Debug().Msgf("Red team scan results: %+v", results)
	if resultsErr != nil {
		return nil, fmt.Errorf("failed to get scan results: %w", resultsErr)
	}

	resultsBytes, err := json.Marshal(results)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal scan results: %w", err)
	}

	workflowData := newWorkflowData("application/json", resultsBytes)
	return []workflow.Data{workflowData}, nil
}

//nolint:ireturn // Unable to change return type of external library
func newWorkflowData(contentType string, data []byte) workflow.Data {
	return workflow.NewData(
		workflow.NewTypeIdentifier(WorkflowID, "redteam"),
		contentType,
		data,
	)
}
