package redteam

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/workflow"

	cli_errors "github.com/snyk/error-catalog-golang-public/cli"
	snyk_common_errors "github.com/snyk/error-catalog-golang-public/snyk"

	redteamclient "github.com/snyk/cli-extension-ai-bom/internal/services/red-team-client"
	"github.com/snyk/cli-extension-ai-bom/internal/utils"

	_ "embed"

	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"

	"github.com/go-playground/validator/v10"
)

var WorkflowID = workflow.NewWorkflowIdentifier("redteam")

const (
	maxPollAttempts = 720
	pollInterval    = 5000 * time.Millisecond
)

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
	config := invocationCtx.GetConfiguration()
	baseAPIURL := config.GetString(configuration.API_URL)
	redTeamClient := redteamclient.NewRedTeamClient(logger, invocationCtx.GetNetworkAccess().GetHttpClient(), userAgent, baseAPIURL)
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

	clientConfig, configData, err := loadAndValidateConfig(logger, config)
	if configData != nil {
		return configData, nil
	}
	if err != nil {
		return nil, err
	}

	logger.Debug().Msg("Starting red team scan")

	scanID, scanErr := redTeamClient.CreateScan(ctx, orgID, clientConfig)
	if scanErr != nil {
		logger.Debug().Err(scanErr).Msg("error while creating scan")
		return nil, *scanErr
	}

	logger.Info().Msgf("Red team scan created with ID: %s", scanID)

	userInterface := invocationCtx.GetUserInterface()
	progressBar, cleanup := setupProgressBar(userInterface, logger, clientConfig.Target.Name)
	defer cleanup()

	scanStatus, pollErr := pollForScanComplete(ctx, logger, redTeamClient, orgID, scanID, progressBar)
	if pollErr != nil {
		logger.Debug().Err(pollErr).Msg("error while polling for the scan")
		return nil, pollErr
	}

	if scanStatus.Status == redteamclient.AIScanStatusFailed {
		return nil, handleScanFailure(scanStatus)
	}

	progressBar.SetTitle("Scan completed")
	if progressErr := progressBar.UpdateProgress(1.0); progressErr != nil {
		logger.Debug().Err(progressErr).Msg("Failed to update progress bar")
	}

	logger.Info().Msgf("Red team scan completed with ID: %s", scanID)

	return getScanResults(ctx, logger, redTeamClient, orgID, scanID)
}

//nolint:ireturn // Unable to change return type of external library
func loadAndValidateConfig(logger *zerolog.Logger, config configuration.Configuration) (*redteamclient.RedTeamConfig, []workflow.Data, error) {
	configPath := config.GetString(utils.FlagConfig)
	if configPath == "" {
		logger.Debug().Msg("No config path provided, using default value.")
		configPath = "redteam.yaml"
	}

	if _, configFileErr := os.Stat(configPath); os.IsNotExist(configFileErr) {
		message := `
Configuration file not found. Please create either a redteam.yaml file in the current directory 
or use the --config flag to specify a custom path.`
		return nil, []workflow.Data{newWorkflowData("text/plain", []byte(message))}, nil
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
		},
	}

	return clientConfig, nil, nil
}

func handleScanFailure(scanStatus *redteamclient.AIScan) error {
	if len(scanStatus.Feedback.Error) > 0 {
		backendError := scanStatus.Feedback.Error[0]
		switch backendError.Code {
		case "context_error":
			return snyk_common_errors.NewBadRequestError(backendError.Message)
		default:
			return snyk_common_errors.NewServerError(backendError.Message)
		}
	}

	return snyk_common_errors.NewServerError("Red team scan has failed without a specific reason.")
}

//nolint:ireturn // Unable to change return type of external library
func setupProgressBar(userInterface ui.UserInterface, logger *zerolog.Logger, targetName string) (progressBar ui.ProgressBar, cleanup func()) {
	progressBar = userInterface.NewProgressBar()
	progressBar.SetTitle(fmt.Sprintf("Starting a scan against %s...", targetName))

	if progressErr := progressBar.UpdateProgress(ui.InfiniteProgress); progressErr != nil {
		logger.Debug().Err(progressErr).Msg("Failed to update progress bar")
	}

	cleanup = func() {
		if clearErr := progressBar.Clear(); clearErr != nil {
			logger.Debug().Err(clearErr).Msg("Failed to clear progress bar")
		}
	}

	return progressBar, cleanup
}

func getScanResults(ctx context.Context, logger *zerolog.Logger, redTeamClient redteamclient.RedTeamClient, orgID, scanID string) ([]workflow.Data, error) {
	results, resultsErr := redTeamClient.GetScanResults(ctx, orgID, scanID)
	logger.Debug().Msgf("Red team scan results: %+v", results)
	if resultsErr != nil {
		logger.Debug().Err(resultsErr).Msg("error while getting scan results")
		return nil, *resultsErr
	}

	resultsBytes, err := json.Marshal(results)
	if err != nil {
		return nil, snyk_common_errors.NewServerError(fmt.Sprintf("failed to marshal scan results: %s", err.Error()))
	}

	workflowData := newWorkflowData("application/json", resultsBytes)
	return []workflow.Data{workflowData}, nil
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

func pollForScanComplete(
	ctx context.Context,
	logger *zerolog.Logger,
	redTeamClient redteamclient.RedTeamClient,
	orgID string,
	scanID string,
	progressBar ui.ProgressBar,
) (*redteamclient.AIScan, error) {
	numberOfPolls := 0

	for numberOfPolls <= maxPollAttempts {
		numberOfPolls++

		scanData, err := redTeamClient.GetScan(ctx, orgID, scanID)
		if err != nil {
			serverErr := snyk_common_errors.NewServerError(fmt.Sprintf("Failed to get scan status: %s", err.Detail))
			return nil, serverErr
		}

		if scanData.Feedback.Status != nil {
			progressBar.SetTitle("Running a scan... It might take a while.")
			if err := progressBar.UpdateProgress(float64(*scanData.Feedback.Status.Done) / float64(*scanData.Feedback.Status.Total)); err != nil {
				logger.Debug().Err(err).Msg("Failed to update progress bar")
			}
		}

		logger.Debug().
			Str("scanID", scanID).
			Str("status", string(scanData.Status)).
			Msg("Polling results for scan")

		if scanData.Status == redteamclient.AIScanStatusCompleted || scanData.Status == redteamclient.AIScanStatusFailed {
			return scanData, nil
		}

		time.Sleep(pollInterval)
	}

	err := snyk_common_errors.NewServerError("Red team scan polling timed out.")
	return nil, err
}

//nolint:ireturn // Unable to change return type of external library
func newWorkflowData(contentType string, data []byte) workflow.Data {
	return workflow.NewData(
		workflow.NewTypeIdentifier(WorkflowID, "redteam"),
		contentType,
		data,
	)
}
