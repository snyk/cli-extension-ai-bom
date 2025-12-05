package redteamscanningagent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	cli_errors "github.com/snyk/error-catalog-golang-public/cli"
	snyk_common_errors "github.com/snyk/error-catalog-golang-public/snyk"

	redteam_errors "github.com/snyk/cli-extension-ai-bom/internal/errors/redteam"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"

	redteamclient "github.com/snyk/cli-extension-ai-bom/internal/services/red-team-client"
	"github.com/snyk/cli-extension-ai-bom/internal/utils"
)

const (
	scanningAgentWorkflowName = "redteam.scanning-agent"
	userAgent                 = "cli-extension-ai-bom-redteam-scanning-agent"
)

var scanningAgentWorkflowID = workflow.NewWorkflowIdentifier(scanningAgentWorkflowName)

func RegisterRedTeamScanningAgentWorkflow(e workflow.Engine) error {
	flagset := pflag.NewFlagSet("snyk-cli-extension-ai-bom-redteam-scanningagent", pflag.ExitOnError)
	flagset.Bool(utils.FlagExperimental, false, "This is an experiment feature that will contain breaking changes in future revisions")
	flagset.String(utils.FlagScanningAgentName, "", "Scanning agent name")
	flagset.Bool(utils.FlagCreateScanningAgent, false, "Create scanning agent")
	flagset.Bool(utils.FlagDeleteScanningAgent, false, "Delete scanning agent")
	flagset.String(utils.FlagScanningAgentID, "", "Scanning agent ID")

	configuration := workflow.ConfigurationOptionsFromFlagset(flagset)
	if _, err := e.Register(scanningAgentWorkflowID, configuration, redTeamScanningAgentWorkflow); err != nil {
		return fmt.Errorf("error while registering red team scanning agent create workflow: %w", err)
	}
	return nil
}

func redTeamScanningAgentWorkflow(invocationCtx workflow.InvocationContext, _ []workflow.Data) (output []workflow.Data, err error) {
	logger := invocationCtx.GetEnhancedLogger()
	config := invocationCtx.GetConfiguration()
	baseAPIURL := config.GetString(configuration.API_URL)
	redTeamClient := redteamclient.NewRedTeamClient(logger, invocationCtx.GetNetworkAccess().GetHttpClient(), userAgent, baseAPIURL)
	return RunRedTeamScanningAgentWorkflow(invocationCtx, redTeamClient)
}

func RunRedTeamScanningAgentWorkflow(invocationCtx workflow.InvocationContext, redTeamClient redteamclient.RedTeamClient) ([]workflow.Data, error) {
	logger := invocationCtx.GetEnhancedLogger()
	config := invocationCtx.GetConfiguration()

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

	createScanningAgent := config.GetBool(utils.FlagCreateScanningAgent)
	deleteScanningAgent := config.GetBool(utils.FlagDeleteScanningAgent)

	if createScanningAgent && deleteScanningAgent {
		return nil, redteam_errors.NewBadRequestError("Cannot create and delete scanning agent at the same time")
	}

	if createScanningAgent {
		return handleCreateScanningAgent(invocationCtx, redTeamClient)
	}

	if deleteScanningAgent {
		return handleDeleteScanningAgent(invocationCtx, redTeamClient)
	}

	return handleListScanningAgents(invocationCtx, redTeamClient)
}

func ScanningAgentConfigMessage(token, apiURL string) string {
	return fmt.Sprintf(`
Agent Token: 
%s

The token will only be displayed once. Please copy it and save it securely.

Installation

Docker:

To install the agent, execute the following command on your terminal:

docker run -d --name probely-agent --cap-add NET_ADMIN -e FARCASTER_AGENT_TOKEN=%s \
-e FARCASTER_API_URL=%s --device /dev/net/tun probely/farcaster-onprem-agent:v3

Then, you can check the agent logs by running the following command:

docker logs -f probely-agent

Check the agent documentation for more details:
https://github.com/Probely/farcaster-onprem-agent
`, token, token, apiURL)
}

func handleCreateScanningAgent(invocationCtx workflow.InvocationContext, redTeamClient redteamclient.RedTeamClient) ([]workflow.Data, error) {
	logger := invocationCtx.GetEnhancedLogger()
	config := invocationCtx.GetConfiguration()
	ctx := context.Background()

	scanningAgentName := config.GetString(utils.FlagScanningAgentName)
	if scanningAgentName == "" {
		scanningAgentName = "agent-" + uuid.New().String()
	}

	logger.Debug().Msgf("Creating scanning agent with name: %s", scanningAgentName)

	orgID := config.GetString(configuration.ORGANIZATION)
	scanningAgent, rtErr := redTeamClient.CreateScanningAgent(ctx, orgID, scanningAgentName)
	if rtErr != nil {
		return nil, rtErr
	}

	logger.Info().Msgf("Scanning agent created with ID: %s", scanningAgent.ID)

	scanningAgentConfig, rtErr := redTeamClient.GenerateScanningAgentConfig(ctx, orgID, scanningAgent.ID)
	if rtErr != nil {
		return nil, rtErr
	}

	logger.Info().Msgf("Scanning agent config generated for agent with ID: %s", scanningAgent.ID)

	agentBytes, err := json.Marshal(scanningAgent)
	if err != nil {
		logger.Debug().Err(err).Msg("error while marshaling scanning agent")
		return nil, redteam_errors.NewGenericRedTeamError("Failed processing scanning agent", err)
	}

	workflowData := []workflow.Data{
		newWorkflowData("application/json", agentBytes),
		newWorkflowData("text/plain", []byte(ScanningAgentConfigMessage(scanningAgentConfig.FarcasterAgentToken, scanningAgentConfig.FarcasterAPIURL))),
	}
	return workflowData, nil
}

func handleDeleteScanningAgent(invocationCtx workflow.InvocationContext, redTeamClient redteamclient.RedTeamClient) ([]workflow.Data, error) {
	logger := invocationCtx.GetEnhancedLogger()
	config := invocationCtx.GetConfiguration()
	ctx := context.Background()

	scanningAgentID := config.GetString(utils.FlagScanningAgentID)
	if scanningAgentID == "" {
		return nil, redteam_errors.NewBadRequestError("No scanning agent ID specified")
	}

	logger.Debug().Msgf("Deleting scanning agent with ID: %s", scanningAgentID)

	orgID := config.GetString(configuration.ORGANIZATION)
	rtErr := redTeamClient.DeleteScanningAgent(ctx, orgID, scanningAgentID)
	if rtErr != nil {
		return nil, rtErr
	}

	logger.Info().Msgf("Scanning agent deleted with ID: %s", scanningAgentID)

	data := map[string]string{
		"id": scanningAgentID,
	}
	resultsBytes, err := json.Marshal(data)
	if err != nil {
		logger.Debug().Err(err).Msg("error while marshaling scanning agent deletion result")
		return nil, redteam_errors.NewGenericRedTeamError("Failed processing scanning agent deletion result", err)
	}

	workflowData := newWorkflowData("application/json", resultsBytes)
	return []workflow.Data{workflowData}, nil
}

func handleListScanningAgents(invocationCtx workflow.InvocationContext, redTeamClient redteamclient.RedTeamClient) ([]workflow.Data, error) {
	logger := invocationCtx.GetEnhancedLogger()
	config := invocationCtx.GetConfiguration()
	ctx := context.Background()

	orgID := config.GetString(configuration.ORGANIZATION)
	scanningAgents, rtErr := redTeamClient.ListScanningAgents(ctx, orgID)
	if rtErr != nil {
		return nil, rtErr
	}

	logger.Info().Msgf("Scanning agents listed for organization ID: %s", orgID)

	resultsBytes, err := json.Marshal(scanningAgents)
	if err != nil {
		logger.Debug().Err(err).Msg("error while marshaling scanning agents")
		return nil, redteam_errors.NewGenericRedTeamError("Failed processing scanning agents", err)
	}

	workflowData := newWorkflowData("application/json", resultsBytes)
	return []workflow.Data{workflowData}, nil
}

//nolint:ireturn // Unable to change return type of external library
func newWorkflowData(contentType string, data []byte) workflow.Data {
	return workflow.NewData(
		workflow.NewTypeIdentifier(scanningAgentWorkflowID, "redteam.scanning-agent"),
		contentType,
		data,
	)
}
