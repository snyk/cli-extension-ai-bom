package redteam

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/workflow"

	cli_errors "github.com/snyk/error-catalog-golang-public/cli"
	snyk_common_errors "github.com/snyk/error-catalog-golang-public/snyk"

	redteam_errors "github.com/snyk/cli-extension-ai-bom/internal/errors/redteam"

	redteamget "github.com/snyk/cli-extension-ai-bom/internal/commands/redteamget"
	scanningagent "github.com/snyk/cli-extension-ai-bom/internal/commands/redteamscanningagent"
	redteamclient "github.com/snyk/cli-extension-ai-bom/internal/services/red-team-client"
	"github.com/snyk/cli-extension-ai-bom/internal/utils"

	_ "embed"

	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"

	"github.com/go-playground/validator/v10"
)

var WorkflowID = workflow.NewWorkflowIdentifier("redteam")

//go:embed redteam-report.html
var redteamHTMLTemplate string

const (
	maxPollDuration = 24 * time.Hour
	pollInterval    = 5000 * time.Millisecond
	maxPollAttempts = int(maxPollDuration / pollInterval)
)

func RegisterWorkflows(e workflow.Engine) error {
	if err := RegisterRedTeamWorkflow(e); err != nil {
		return fmt.Errorf("error while registering red team workflow: %w", err)
	}
	if err := redteamget.RegisterRedTeamGetWorkflow(e); err != nil {
		return fmt.Errorf("error while registering red team get workflow: %w", err)
	}
	if err := scanningagent.RegisterRedTeamScanningAgentWorkflows(e); err != nil {
		return fmt.Errorf("error while registering red team scanning agent workflow: %w", err)
	}
	return nil
}

func RegisterRedTeamWorkflow(e workflow.Engine) error {
	flagset := pflag.NewFlagSet("snyk-cli-extension-ai-bom-redteam", pflag.ExitOnError)
	flagset.Bool(utils.FlagExperimental, false, "This is an experiment feature that will contain breaking changes in future revisions")
	flagset.Bool(utils.FlagHTML, false, "Output the red team report in HTML format instead of JSON")
	flagset.String(utils.FlagHTMLFileOutput, "", "Write the HTML report to the specified file path")
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

	results, err := handleRunScanCommand(invocationCtx, redTeamClient)
	if err != nil {
		return nil, err
	}
	return results, nil
}

func handleRunScanCommand(invocationCtx workflow.InvocationContext, redTeamClient redteamclient.RedTeamClient) ([]workflow.Data, *redteam_errors.RedTeamError) {
	logger := invocationCtx.GetEnhancedLogger()
	config := invocationCtx.GetConfiguration()
	ctx := context.Background()

	orgID := config.GetString(configuration.ORGANIZATION)

	clientConfig, configData, err := LoadAndValidateConfig(logger, config)
	if configData != nil {
		return configData, nil
	}
	if err != nil {
		return nil, redteam_errors.NewBadRequestError(err.Error())
	}

	logger.Debug().Msg("Starting red team scan")

	scanID, scanErr := redTeamClient.CreateScan(ctx, orgID, clientConfig)
	if scanErr != nil {
		return nil, scanErr
	}

	logger.Info().Msgf("Red team scan created with ID: %s", scanID)

	userInterface := invocationCtx.GetUserInterface()
	progressBar, cleanup := setupProgressBar(userInterface, logger, clientConfig.Target.Name)
	defer cleanup()

	scanStatus, pollErr := pollForScanComplete(ctx, logger, redTeamClient, orgID, scanID, progressBar, userInterface)
	if pollErr != nil {
		return nil, pollErr
	}

	if scanStatus.Status == redteamclient.AIScanStatusFailed {
		return nil, handleScanFailure(scanStatus, scanID)
	}

	progressBar.SetTitle("Scan completed")
	if progressErr := progressBar.UpdateProgress(1.0); progressErr != nil {
		logger.Debug().Err(progressErr).Msg("Failed to update progress bar")
	}

	logger.Info().Msgf("Red team scan completed with ID: %s", scanID)

	results, resultsErr := getScanResults(ctx, logger, redTeamClient, orgID, scanID)
	if resultsErr != nil {
		return nil, resultsErr
	}

	returnHTML := config.GetBool(utils.FlagHTML)
	htmlFileOutput := config.GetString(utils.FlagHTMLFileOutput)
	needsHTML := returnHTML || htmlFileOutput != ""

	var htmlOutput string
	if needsHTML {
		var htmlErr error
		htmlOutput, htmlErr = htmlFromResults(results)
		if htmlErr != nil {
			logger.Debug().Err(htmlErr).Msg("error while generating HTML report")
			return nil, redteam_errors.NewGenericRedTeamError("Failed generating HTML report", htmlErr)
		}
	}

	if htmlFileOutput != "" {
		if writeErr := os.WriteFile(htmlFileOutput, []byte(htmlOutput), 0o600); writeErr != nil {
			logger.Debug().Err(writeErr).Msgf("error writing HTML report to %s", htmlFileOutput)
			return nil, redteam_errors.NewGenericRedTeamError(fmt.Sprintf("Failed writing HTML report to %s", htmlFileOutput), writeErr)
		}

		logger.Info().Msgf("HTML report written to %s", htmlFileOutput)
	}

	if returnHTML {
		return []workflow.Data{newWorkflowData("text/html", []byte(htmlOutput))}, nil
	}

	return results, nil
}

//nolint:ireturn,nolintlint // Unable to change return type of external library
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

func handleScanFailure(scanStatus *redteamclient.AIScan, scanID string) *redteam_errors.RedTeamError {
	if len(scanStatus.Feedback.Error) > 0 {
		backendError := scanStatus.Feedback.Error[0]

		switch backendError.Code {
		case "context_error":
			return redteam_errors.NewScanContextError(backendError.Message, scanID)
		case "network_error":
			return redteam_errors.NewScanNetworkError(backendError.Message, scanID)
		default:
			errorMsg := fmt.Sprintf(
				"Red teaming scan (ID: %s) failed. \nError type: %s \nMessage: %s",
				scanID,
				backendError.Code,
				backendError.Message,
			)
			return redteam_errors.NewScanError(errorMsg, scanID)
		}
	}

	return redteam_errors.NewScanError("We couldn't determine the details. Contact support for more information.", scanID)
}

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

func getScanResults(
	ctx context.Context,
	logger *zerolog.Logger,
	redTeamClient redteamclient.RedTeamClient,
	orgID, scanID string,
) ([]workflow.Data, *redteam_errors.RedTeamError) {
	results, resultsErr := redTeamClient.GetScanResults(ctx, orgID, scanID)
	logger.Debug().Msgf("Red team scan results: %+v", results)
	if resultsErr != nil {
		logger.Debug().Err(resultsErr).Msg("error while getting scan results")
		return nil, resultsErr
	}

	resultsBytes, err := json.Marshal(results)
	if err != nil {
		logger.Debug().Err(err).Msg("error while marshaling scan results")
		return nil, redteam_errors.NewGenericRedTeamError("Failed processing scan results", err)
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

type vulnerabilityCounts struct {
	criticals int
	highs     int
	mediums   int
	lows      int
}

func (v vulnerabilityCounts) total() int {
	return v.criticals + v.highs + v.mediums + v.lows
}

func (v vulnerabilityCounts) hasChanged(other vulnerabilityCounts) bool {
	return v.criticals != other.criticals ||
		v.highs != other.highs ||
		v.mediums != other.mediums ||
		v.lows != other.lows
}

func getVulnerabilityCounts(scanData *redteamclient.AIScan) vulnerabilityCounts {
	counts := vulnerabilityCounts{}
	if scanData.Criticals != nil {
		counts.criticals = *scanData.Criticals
	}
	if scanData.Highs != nil {
		counts.highs = *scanData.Highs
	}
	if scanData.Mediums != nil {
		counts.mediums = *scanData.Mediums
	}
	if scanData.Lows != nil {
		counts.lows = *scanData.Lows
	}
	return counts
}

func pollForScanComplete(
	ctx context.Context,
	logger *zerolog.Logger,
	redTeamClient redteamclient.RedTeamClient,
	orgID string,
	scanID string,
	progressBar ui.ProgressBar,
	userInterface ui.UserInterface,
) (*redteamclient.AIScan, *redteam_errors.RedTeamError) {
	numberOfPolls := 0
	prevCounts := vulnerabilityCounts{}

	for numberOfPolls <= maxPollAttempts {
		numberOfPolls++

		scanData, err := redTeamClient.GetScan(ctx, orgID, scanID)
		if err != nil {
			return nil, err
		}

		if scanData.Feedback.Status != nil {
			progressBar.SetTitle(fmt.Sprintf("Scanning %s (%d/%d)", scanData.Target.Name, *scanData.Feedback.Status.Done, *scanData.Feedback.Status.Total))
		}

		currentCounts := getVulnerabilityCounts(scanData)
		if currentCounts.total() > 0 && currentCounts.hasChanged(prevCounts) {
			outputVulnerabilityFindings(userInterface, logger, currentCounts)
			prevCounts = currentCounts
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

	logger.Debug().Msgf("Polling timed out on scan ID: %s. This should not happen in reality.", scanID)
	return nil, redteam_errors.NewPollingTimeoutError()
}

func outputVulnerabilityFindings(userInterface ui.UserInterface, logger *zerolog.Logger, counts vulnerabilityCounts) {
	message := fmt.Sprintf("\nNew vulnerabilities found. Total: %d Critical, %d High, %d Medium, %d Low",
		counts.criticals, counts.highs, counts.mediums, counts.lows)
	if err := userInterface.Output(message); err != nil {
		logger.Debug().Err(err).Msg("Failed to output vulnerability findings")
	}
}

func htmlFromResults(results []workflow.Data) (string, error) {
	if len(results) == 0 {
		return "", fmt.Errorf("no results to generate HTML from")
	}

	payload, ok := results[0].GetPayload().([]byte)
	if !ok {
		return "", fmt.Errorf("unexpected payload type")
	}

	return generateRedTeamHTML(string(payload))
}

func generateRedTeamHTML(jsonData string) (string, error) {
	tmpl, err := template.New("redteam-report").Parse(redteamHTMLTemplate)
	if err != nil {
		return "", fmt.Errorf("error parsing HTML template: %w", err)
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, jsonData); err != nil {
		return "", fmt.Errorf("error executing HTML template: %w", err)
	}

	return buf.String(), nil
}

func newWorkflowData(contentType string, data []byte) workflow.Data {
	return workflow.NewData(
		workflow.NewTypeIdentifier(WorkflowID, "redteam"),
		contentType,
		data,
	)
}
