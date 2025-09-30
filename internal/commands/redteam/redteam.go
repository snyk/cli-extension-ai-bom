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
)

var WorkflowID = workflow.NewWorkflowIdentifier("redteam")

func RegisterWorkflows(e workflow.Engine) error {
	flagset := pflag.NewFlagSet("snyk-cli-extension-ai-bom-redteam", pflag.ExitOnError)
	flagset.Bool(utils.FlagExperimental, false, "This is an experiment feature that will contain breaking changes in future revisions")

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

// Config represents the configuration structure for red team scans.
type Config struct {
	Options Options  `yaml:"options"`
	Attacks []string `yaml:"attacks,omitempty"`
}

type Options struct {
	Target TargetConfig `yaml:"target"`
}

type TargetConfig struct {
	Name             string            `yaml:"name"`
	URL              string            `yaml:"url"`
	Method           string            `yaml:"method,omitempty"`
	Headers          map[string]string `yaml:"headers,omitempty"`
	ResponseSelector string            `yaml:"response_selector,omitempty"`
	RequestTemplate  string            `yaml:"request_template,omitempty"`
}

func RunRedTeamWorkflow(
	invocationCtx workflow.InvocationContext,
	redTeamClient redteamclient.RedTeamClient,
) ([]workflow.Data, error) {
	logger := invocationCtx.GetEnhancedLogger()
	config := invocationCtx.GetConfiguration()

	config.Set(configuration.RAW_CMD_ARGS, os.Args[1:])
	experimental := config.GetBool(utils.FlagExperimental)

	// As this is an experimental feature, we only want to continue if the experimental flag is set
	if !experimental {
		logger.Debug().Msg("Required experimental flag is not present")
		return nil, cli_errors.NewCommandIsExperimentalError("")
	}

	orgID := config.GetString(configuration.ORGANIZATION)

	if orgID == "" {
		logger.Debug().Msg("no org id found")
		return nil, snyk_common_errors.NewUnauthorisedError("")
	}
	logger.Debug().Msgf("running command with orgId: %s", orgID)

	return handleRunScanCommand(invocationCtx, redTeamClient)
}

func handleRunScanCommand(invocationCtx workflow.InvocationContext, redTeamClient redteamclient.RedTeamClient) ([]workflow.Data, error) {
	logger := invocationCtx.GetEnhancedLogger()
	config := invocationCtx.GetConfiguration()
	ctx := context.Background()
	orgID := config.GetString(configuration.ORGANIZATION)

	configPath := config.GetString("config")
	if configPath == "" {
		configPath = "redteam.yaml"
	}

	// Check if config file exists
	if _, configFileErr := os.Stat(configPath); os.IsNotExist(configFileErr) {
		message := "Configuration file not found. Please create redteam.yaml file in the current directory. " +
			"See the documentation (link here) on how to create one."
		return []workflow.Data{newWorkflowData("text/plain", []byte(message))}, nil
	}

	// Load configuration
	configData, configErr := os.ReadFile(configPath)
	if configErr != nil {
		logger.Debug().Err(configErr).Msg("error while reading config file")
		return nil, errors.NewInternalError("Error reading configuration file").SnykError
	}

	var redTeamConfig Config
	yamlErr := yaml.Unmarshal(configData, &redTeamConfig)
	if yamlErr != nil {
		logger.Debug().Err(yamlErr).Msg("error while unmarshaling config")
		return nil, snyk_common_errors.NewServerError("Error parsing configuration file")
	}

	// Convert to client config
	clientConfig := redteamclient.RedTeamConfig{
		Options: redteamclient.RedTeamOptions{
			Target: redteamclient.TargetConfig{
				Name:             redTeamConfig.Options.Target.Name,
				URL:              redTeamConfig.Options.Target.URL,
				Method:           redTeamConfig.Options.Target.Method,
				Headers:          redTeamConfig.Options.Target.Headers,
				ResponseSelector: redTeamConfig.Options.Target.ResponseSelector,
				RequestTemplate:  redTeamConfig.Options.Target.RequestTemplate,
			},
		},
		Attacks: redTeamConfig.Attacks,
	}

	apiErr := redTeamClient.ValidateTarget(ctx, orgID, &clientConfig)

	if apiErr != nil {
		logger.Debug().Msg("Target is not available or misconfigured")
		return nil, apiErr
	}

	logger.Debug().Msg("Starting red team scan")

	scanID, scanErr := redTeamClient.RunScan(ctx, orgID, &clientConfig)

	if scanErr != nil {
		return nil, fmt.Errorf("failed to create scan: %w", scanErr)
	}

	logger.Info().Msgf("Red team scan started with ID: %s", scanID)

	results, resultsErr := redTeamClient.GetScanResults(ctx, orgID, scanID)
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

func newWorkflowData(contentType string, data []byte) workflow.Data {
	return workflow.NewData(
		workflow.NewTypeIdentifier(WorkflowID, "redteam"),
		contentType,
		data,
	)
}
