package redteam

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

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
	flagset.String("config", "redteam.yaml", "Path to the red team configuration file")
	flagset.String("name", "", "Name of the target (for init command)")
	flagset.String("url", "", "URL of the target (for init command)")
	flagset.String("scan-id", "", "Scan ID for get scan command")

	configuration := workflow.ConfigurationOptionsFromFlagset(flagset)
	if _, err := e.Register(WorkflowID, configuration, RedTeamWorkflow); err != nil {
		return fmt.Errorf("error while registering red team workflow: %w", err)
	}
	return nil
}

var userAgent = "cli-extension-ai-bom-redteam"

func RedTeamWorkflow(invocationCtx workflow.InvocationContext, _ []workflow.Data) (output []workflow.Data, err error) {
	logger := invocationCtx.GetEnhancedLogger()
	ui := invocationCtx.GetUserInterface()
	config := invocationCtx.GetConfiguration()
	baseAPIURL := config.GetString(configuration.API_URL)
	redTeamClient := redteamclient.NewRedTeamClient(logger, invocationCtx.GetNetworkAccess().GetHttpClient(), ui, userAgent, baseAPIURL)
	return RunRedTeamWorkflow(invocationCtx, redTeamClient)
}

// RedTeamConfig represents the configuration structure for red team scans
type RedTeamConfig struct {
	Options RedTeamOptions `yaml:"options"`
	Attacks []string       `yaml:"attacks,omitempty"`
}

type RedTeamOptions struct {
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
		return nil, errors.NewCommandIsExperimentalError().SnykError
	}

	ctx := context.Background()
	orgID := config.GetString(configuration.ORGANIZATION)
	if orgID == "" {
		logger.Debug().Msg("no org id found")
		return nil, errors.NewUnauthorizedError("").SnykError
	}
	logger.Debug().Msgf("running command with orgId: %s", orgID)

	logger.Debug().Msg("checking api availability")
	apiErr := redTeamClient.CheckAPIAvailability(ctx, orgID)
	if apiErr != nil {
		logger.Debug().Msg("api availability check failed")
		// TODO: check if this doesn't need to be custom
		return nil, apiErr.SnykError
	}

	// Determine the command based on arguments
	args := os.Args[1:]
	if len(args) > 1 {
		switch args[1] {
		case "init":
			return handleInitCommand(invocationCtx, redTeamClient)
		case "get":
			if len(args) > 2 {
				switch args[2] {
				case "scans":
					return handleListScansCommand(invocationCtx, redTeamClient)
				case "scan":
					return handleGetScanCommand(invocationCtx, redTeamClient)
				}
			}
		}
	}

	// Default: run a new scan
	return handleRunScanCommand(invocationCtx, redTeamClient)
}

func handleInitCommand(invocationCtx workflow.InvocationContext, redTeamClient redteamclient.RedTeamClient) ([]workflow.Data, error) {
	logger := invocationCtx.GetEnhancedLogger()
	config := invocationCtx.GetConfiguration()

	name := config.GetString("name")
	url := config.GetString("url")

	if name == "" || url == "" {
		return nil, errors.NewInternalError("Both --name and --url are required for init command").SnykError
	}

	configPath := config.GetString("config")
	if configPath == "" {
		configPath = "redteam.yaml"
	}

	redTeamConfig := RedTeamConfig{
		Options: RedTeamOptions{
			Target: TargetConfig{
				Name:   name,
				URL:    url,
				Method: "POST",
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
			},
		},
	}

	yamlData, err := yaml.Marshal(redTeamConfig)
	if err != nil {
		logger.Debug().Err(err).Msg("error while marshaling red team config")
		return nil, errors.NewInternalError("Error creating configuration file").SnykError
	}

	err = os.WriteFile(configPath, yamlData, 0644)
	if err != nil {
		logger.Debug().Err(err).Msg("error while writing config file")
		return nil, errors.NewInternalError("Error writing configuration file").SnykError
	}

	logger.Info().Msgf("Created red team configuration file: %s", configPath)
	return []workflow.Data{}, nil
}

func handleListScansCommand(invocationCtx workflow.InvocationContext, redTeamClient redteamclient.RedTeamClient) ([]workflow.Data, error) {
	logger := invocationCtx.GetEnhancedLogger()
	config := invocationCtx.GetConfiguration()
	ctx := context.Background()
	orgID := config.GetString(configuration.ORGANIZATION)

	scans, err := redTeamClient.ListScans(ctx, orgID)
	if err != nil {
		logger.Debug().Err(err.SnykError).Msg("error while listing scans")
		return nil, err.SnykError
	}

	// Format the output
	var output strings.Builder
	output.WriteString("Red Team Scans:\n")
	output.WriteString("ID\t\t\t\tStatus\t\tCreated\n")
	output.WriteString("--\t\t\t\t------\t\t-------\n")

	for _, scan := range scans {
		output.WriteString(fmt.Sprintf("%s\t%s\t\t%s\n",
			scan.Id,
			scan.Attributes.Status,
			scan.Attributes.CreatedAt.Format("2006-01-02 15:04:05")))
	}

	workflowData := newWorkflowData("text/plain", []byte(output.String()))
	return []workflow.Data{workflowData}, nil
}

func handleGetScanCommand(invocationCtx workflow.InvocationContext, redTeamClient redteamclient.RedTeamClient) ([]workflow.Data, error) {
	logger := invocationCtx.GetEnhancedLogger()
	config := invocationCtx.GetConfiguration()
	ctx := context.Background()
	orgID := config.GetString(configuration.ORGANIZATION)
	scanID := config.GetString("scan-id")

	if scanID == "" {
		return nil, errors.NewInternalError("Scan ID is required for get scan command").SnykError
	}

	scanStatus, err := redTeamClient.GetScan(ctx, orgID, scanID)
	if err != nil {
		logger.Debug().Err(err.SnykError).Msg("error while getting scan")
		return nil, err.SnykError
	}

	// Format the output
	var output strings.Builder
	output.WriteString(fmt.Sprintf("Scan ID: %s\n", scanStatus.Id))
	output.WriteString(fmt.Sprintf("Status: %s\n", scanStatus.Attributes.Status))
	output.WriteString(fmt.Sprintf("Created: %s\n", scanStatus.Attributes.CreatedAt.Format("2006-01-02 15:04:05")))
	output.WriteString(fmt.Sprintf("Updated: %s\n", scanStatus.Attributes.UpdatedAt.Format("2006-01-02 15:04:05")))

	// If scan is completed, also get the results
	if scanStatus.Attributes.Status == "completed" {
		results, err := redTeamClient.GetScanResults(ctx, orgID, scanID)
		if err != nil {
			logger.Debug().Err(err.SnykError).Msg("error while getting scan results")
			return nil, err.SnykError
		}
		output.WriteString(fmt.Sprintf("\nResults:\n%s\n", results))
	}

	workflowData := newWorkflowData("text/plain", []byte(output.String()))
	return []workflow.Data{workflowData}, nil
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
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		logger.Error().Msgf("Configuration file %s not found. Run 'snyk redteam init' to create one.", configPath)
		return nil, errors.NewInternalError("Configuration file not found").SnykError
	}

	// Load configuration
	configData, err := os.ReadFile(configPath)
	if err != nil {
		logger.Debug().Err(err).Msg("error while reading config file")
		return nil, errors.NewInternalError("Error reading configuration file").SnykError
	}

	var redTeamConfig RedTeamConfig
	err = yaml.Unmarshal(configData, &redTeamConfig)
	if err != nil {
		logger.Debug().Err(err).Msg("error while unmarshaling config")
		return nil, errors.NewInternalError("Error parsing configuration file").SnykError
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

	logger.Debug().Msg("Starting red team scan")
	scanID, aiBomErr := redTeamClient.CreateScan(ctx, orgID, clientConfig)
	if aiBomErr != nil {
		logger.Debug().Err(aiBomErr.SnykError).Msg("error while creating scan")
		return nil, aiBomErr.SnykError
	}

	logger.Info().Msgf("Red team scan started with ID: %s", scanID)

	// Get the results
	results, aiBomErr := redTeamClient.GetScanResults(ctx, orgID, scanID)
	if aiBomErr != nil {
		logger.Debug().Err(aiBomErr.SnykError).Msg("error while getting scan results")
		return nil, aiBomErr.SnykError
	}

	workflowData := newWorkflowData("application/json", []byte(results))
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
