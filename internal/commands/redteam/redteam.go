package redteam

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	cli_errors "github.com/snyk/error-catalog-golang-public/cli"

	redteam_errors "github.com/snyk/cli-extension-ai-bom/internal/errors/redteam"

	"github.com/snyk/cli-extension-ai-bom/internal/commands/redagent"
	"github.com/snyk/cli-extension-ai-bom/internal/commands/redteam/tui"
	scanningagent "github.com/snyk/cli-extension-ai-bom/internal/commands/redteamscanningagent"
	redteamclient "github.com/snyk/cli-extension-ai-bom/internal/services/red-team-client"
	"github.com/snyk/cli-extension-ai-bom/internal/utils"

	_ "embed"

	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"

	"github.com/go-playground/validator/v10"
)

var (
	WorkflowID                  = workflow.NewWorkflowIdentifier("redteam")
	ErrConfigNotFound           = fmt.Errorf("configuration file not found")
	In                io.Reader = os.Stdin
	Out               io.Writer = os.Stdout
)

func RegisterWorkflows(e workflow.Engine) error {
	if err := redagent.RegisterWorkflows(e); err != nil {
		return fmt.Errorf("error while registering red team workflow: %w", err)
	}
	if err := RegisterRedTeamWorkflow(e); err != nil {
		return fmt.Errorf("error while registering red team workflow: %w", err)
	}
	if err := scanningagent.RegisterRedTeamScanningAgentWorkflows(e); err != nil {
		return fmt.Errorf("error while registering red team scanning agent workflow: %w", err)
	}
	return nil
}

func RegisterRedTeamWorkflow(e workflow.Engine) error {
	flagset := pflag.NewFlagSet("snyk-cli-extension-ai-bom-redteam", pflag.ExitOnError)
	flagset.Bool(utils.FlagExperimental, false, "This is an experiment feature that will contain breaking changes in future revisions")
	flagset.String(utils.FlagConfig, "redteam.yaml", "Path to the red team configuration file")
	flagset.String(utils.FlagRedTeamScanningAgentID, "", "Scanning agent ID (overrides configuration file)")

	configuration := workflow.ConfigurationOptionsFromFlagset(flagset)
	if _, err := e.Register(WorkflowID, configuration, redTeamWorkflow); err != nil {
		return fmt.Errorf("error while registering red team workflow: %w", err)
	}
	return nil
}

var userAgent = "cli-extension-ai-bom-redteam"

func redTeamWorkflow(invocationCtx workflow.InvocationContext, _ []workflow.Data) (output []workflow.Data, err error) {
	logger := invocationCtx.GetEnhancedLogger()
	config := invocationCtx.GetConfiguration()
	baseAPIURL := config.GetString(configuration.API_URL)

	// Check if debug flag is explicitly present in arguments
	// We do this to override potential defaults that might enable debug logging
	hasDebugFlag := false
	for _, arg := range os.Args {
		if arg == "--debug" {
			hasDebugFlag = true
			break
		}
	}

	if !hasDebugFlag {
		l := logger.Level(zerolog.InfoLevel)
		logger = &l
	}

	redTeamClient := redteamclient.NewRedTeamClient(logger, invocationCtx.GetNetworkAccess().GetHttpClient(), userAgent, baseAPIURL)
	return RunRedTeamWorkflow(invocationCtx, redTeamClient, logger)
}

func RunRedTeamWorkflow(
	invocationCtx workflow.InvocationContext,
	redTeamClient redteamclient.RedTeamClient,
	logger *zerolog.Logger,
) ([]workflow.Data, error) {
	// If logger is nil (e.g. called from tests without updated signature), fallback
	if logger == nil {
		logger = invocationCtx.GetEnhancedLogger()
	}

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
		// We might be in the onboarding flow, so let's allow it to proceed.
		// The handleRunScanCommand or TUI will handle the missing OrgID.
	}

	results, err := handleRunScanCommand(invocationCtx, redTeamClient, logger)
	if err != nil {
		return nil, err
	}
	return results, nil
}

func handleRunScanCommand(
	invocationCtx workflow.InvocationContext,
	redTeamClient redteamclient.RedTeamClient,
	logger *zerolog.Logger,
) ([]workflow.Data, *redteam_errors.RedTeamError) {
	// If logger is nil (fallback)
	if logger == nil {
		logger = invocationCtx.GetEnhancedLogger()
	}

	config := invocationCtx.GetConfiguration()
	ctx := context.Background()

	orgID := config.GetString(configuration.ORGANIZATION)

	clientConfig, configData, err := LoadAndValidateConfig(logger, config)

	// If the config file exists but is invalid (YAML error, etc), LoadAndValidateConfig returns a message in configData
	// IMPORTANT: We only return early if it's NOT a "config not found" error, because we want to fall back to TUI in that case.
	// But wait, LoadAndValidateConfig returns ErrConfigNotFound in the err return value, AND a message in configData.
	// So we need to check err first.

	if !errors.Is(err, ErrConfigNotFound) && configData != nil {
		return configData, nil
	}

	// If there was a validation error (logic error in config), return it
	if err != nil && !errors.Is(err, ErrConfigNotFound) {
		return nil, redteam_errors.NewBadRequestError(err.Error())
	}

	// Determine initial config
	var initConfig *redteamclient.RedTeamConfig
	if err == nil {
		initConfig = clientConfig
	}

	// Start Interactive TUI
	data, tuiErr := tui.Run(ctx, redTeamClient, orgID, invocationCtx, initConfig, In, Out)
	if tuiErr != nil {
		return nil, redteam_errors.NewGenericRedTeamError(fmt.Sprintf("TUI failed: %v", tuiErr), tuiErr)
	}
	return data, nil
}

func LoadAndValidateConfig(logger *zerolog.Logger, config configuration.Configuration) (*redteamclient.RedTeamConfig, []workflow.Data, error) {
	configPath := config.GetString(utils.FlagConfig)
	if configPath == "" {
		logger.Debug().Msg("No config path provided, using default value.")
		configPath = "redteam.yaml"
	}

	if _, configFileErr := os.Stat(configPath); os.IsNotExist(configFileErr) {
		message := `
Configuration file not found. Please create either a redteam.yaml file in the current directory 
or use the --config flag to specify a custom path.`
		return nil, []workflow.Data{newWorkflowData("text/plain", []byte(message))}, ErrConfigNotFound
	}

	invalidConfigMessage := getInvalidConfigMessage()

	configData, configErr := os.ReadFile(configPath)
	if configErr != nil {
		logger.Debug().Err(configErr).Msg("error while reading config file")
		return nil, []workflow.Data{newWorkflowData("text/plain", []byte(invalidConfigMessage))}, nil
	}

	var redTeamConfig redteamclient.RedTeamConfig
	yamlErr := yaml.Unmarshal(configData, &redTeamConfig)
	if yamlErr != nil {
		logger.Debug().Err(yamlErr).Msg("error while unmarshaling config")
		return nil, []workflow.Data{newWorkflowData("text/plain", []byte(invalidConfigMessage))}, nil
	}

	validate := validator.New()
	clientConfigErr := validate.Struct(redTeamConfig)
	if clientConfigErr != nil {
		return nil, nil, cli_errors.NewValidationFailureError(clientConfigErr.Error())
	}

	clientConfig := &redteamclient.RedTeamConfig{
		Target: redteamclient.AIScanTarget{
			Name:     redTeamConfig.Target.Name,
			Type:     redTeamConfig.Target.Type,
			Context:  redTeamConfig.Target.Context,
			Settings: redTeamConfig.Target.Settings,
		},
		Options: redteamclient.AIScanOptions{
			VulnDefinitions: redTeamConfig.Options.VulnDefinitions,
			ScanningAgent:   redTeamConfig.Options.ScanningAgent,
		},
	}

	scanningAgentIDOverride := config.GetString(utils.FlagRedTeamScanningAgentID)
	if scanningAgentIDOverride != "" {
		clientConfigErr := validate.Var(scanningAgentIDOverride, "uuid")
		if clientConfigErr != nil {
			return nil, nil, fmt.Errorf("Scanning agent ID is not a valid UUID: \"%s\"", scanningAgentIDOverride)
		}
		clientConfig.Options.ScanningAgent = scanningAgentIDOverride
	}

	return clientConfig, nil, nil
}

func getInvalidConfigMessage() string {
	return `
	Configuration file in invalid. Please refer to the following example:

	target:
		name: <required, name your target> // Can be anything you want
		type: <required, e.g., api or socket_io> // The type of target to scan
		settings:
			url: '<required, e.g., https://vulnerable-app.com/chat/completions>' // The URL to scan
			headers: // Optional.
				- name: '<optional, e.g. Authorization>' // Authentication header.
				  value: '<optional, e.g. Bearer TOKEN>' // Authentication header.
			response_selector: '<required, e.g., response>' // The path to the response in the JSON response payload
			request_body_template: '<required, e.g., {"message": "{{prompt}}"}>' // The request body template to use for the scan
	
	For more configuration options, refer to the documentation.

	`
}

func newWorkflowData(contentType string, data []byte) workflow.Data {
	return workflow.NewData(
		workflow.NewTypeIdentifier(WorkflowID, "redteam"),
		contentType,
		data,
	)
}
