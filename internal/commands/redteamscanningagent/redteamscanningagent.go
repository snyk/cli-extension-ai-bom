package redteamscanningagent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-playground/validator/v10"
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
	scanningAgentWorkflowName       = "redteam.scanning-agent"
	scanningAgentCreateWorkflowName = "redteam.scanning-agent.create"
	scanningAgentDeleteWorkflowName = "redteam.scanning-agent.delete"
	userAgent                       = "cli-extension-ai-bom-redteam-scanning-agent"
)

var (
	scanningAgentWorkflowID         = workflow.NewWorkflowIdentifier(scanningAgentWorkflowName)
	scanningAgentCreateWorkflowID   = workflow.NewWorkflowIdentifier(scanningAgentCreateWorkflowName)
	scanningAgentDeleteWorkflowID   = workflow.NewWorkflowIdentifier(scanningAgentDeleteWorkflowName)
	scanningAgentWorkflowType       = workflow.NewTypeIdentifier(scanningAgentWorkflowID, scanningAgentWorkflowName)
	scanningAgentCreateWorkflowType = workflow.NewTypeIdentifier(scanningAgentCreateWorkflowID, scanningAgentCreateWorkflowName)
	scanningAgentDeleteWorkflowType = workflow.NewTypeIdentifier(scanningAgentDeleteWorkflowID, scanningAgentDeleteWorkflowName)
)

func RegisterRedTeamScanningAgentWorkflows(e workflow.Engine) error {
	if err := RegisterScanningAgentWorkflow(e); err != nil {
		return err
	}

	if err := RegisterScanningAgentCreateWorkflow(e); err != nil {
		return err
	}

	return RegisterScanningAgentDeleteWorkflow(e)
}

func commonFlagset(suffix string) *pflag.FlagSet {
	name := "snyk-cli-extension-ai-bom-redteam-scanningagent"
	if suffix != "" {
		name += "-" + suffix
	}
	flagset := pflag.NewFlagSet(name, pflag.ExitOnError)
	flagset.Bool(utils.FlagExperimental, false, "This is an experiment feature that will contain breaking changes in future revisions")
	return flagset
}

func RegisterScanningAgentWorkflow(e workflow.Engine) error {
	flagset := commonFlagset("")

	configuration := workflow.ConfigurationOptionsFromFlagset(flagset)
	if _, err := e.Register(scanningAgentWorkflowID, configuration, redTeamScanningAgentWorkflow); err != nil {
		return fmt.Errorf("error while registering red team scanning agent workflow: %w", err)
	}
	return nil
}

func RegisterScanningAgentCreateWorkflow(e workflow.Engine) error {
	flagset := commonFlagset("create")
	flagset.String(utils.FlagScanningAgentName, "", "Scanning agent name")

	configuration := workflow.ConfigurationOptionsFromFlagset(flagset)
	if _, err := e.Register(scanningAgentCreateWorkflowID, configuration, redTeamScanningAgentCreateWorkflow); err != nil {
		return fmt.Errorf("error while registering red team scanning agent create workflow: %w", err)
	}
	return nil
}

func RegisterScanningAgentDeleteWorkflow(e workflow.Engine) error {
	flagset := commonFlagset("delete")
	flagset.String(utils.FlagScanningAgentID, "", "Scanning agent ID")

	configuration := workflow.ConfigurationOptionsFromFlagset(flagset)
	if _, err := e.Register(scanningAgentDeleteWorkflowID, configuration, redTeamScanningAgentDeleteWorkflow); err != nil {
		return fmt.Errorf("error while registering red team scanning agent delete workflow: %w", err)
	}
	return nil
}

func getRedTeamClient(invocationCtx workflow.InvocationContext) *redteamclient.ClientImpl {
	logger := invocationCtx.GetEnhancedLogger()
	config := invocationCtx.GetConfiguration()
	baseAPIURL := config.GetString(configuration.API_URL)
	return redteamclient.NewRedTeamClient(logger, invocationCtx.GetNetworkAccess().GetHttpClient(), userAgent, baseAPIURL)
}

func redTeamScanningAgentWorkflow(invocationCtx workflow.InvocationContext, _ []workflow.Data) (output []workflow.Data, err error) {
	return RunRedTeamScanningAgentWorkflow(invocationCtx, getRedTeamClient(invocationCtx))
}

func redTeamScanningAgentCreateWorkflow(invocationCtx workflow.InvocationContext, _ []workflow.Data) (output []workflow.Data, err error) {
	return RunRedTeamScanningAgentCreateWorkflow(invocationCtx, getRedTeamClient(invocationCtx))
}

func redTeamScanningAgentDeleteWorkflow(invocationCtx workflow.InvocationContext, _ []workflow.Data) (output []workflow.Data, err error) {
	return RunRedTeamScanningAgentDeleteWorkflow(invocationCtx, getRedTeamClient(invocationCtx))
}

func commonRedTeamScanningAgentWorkflow(invocationCtx workflow.InvocationContext) error {
	logger := invocationCtx.GetEnhancedLogger()
	config := invocationCtx.GetConfiguration()

	experimental := config.GetBool(utils.FlagExperimental)
	if !experimental {
		logger.Debug().Msg("Required experimental flag is not present")
		return cli_errors.NewCommandIsExperimentalError("")
	}

	orgID := config.GetString(configuration.ORGANIZATION)
	if orgID == "" {
		logger.Debug().Msg("No organization id is found.")
		// This shouldn't really happen unless customer has explicitly unset the orgId.
		return snyk_common_errors.NewUnauthorisedError("")
	}

	return nil
}

func RunRedTeamScanningAgentWorkflow(invocationCtx workflow.InvocationContext, redTeamClient redteamclient.RedTeamClient) ([]workflow.Data, error) {
	if err := commonRedTeamScanningAgentWorkflow(invocationCtx); err != nil {
		return nil, err
	}

	return handleListScanningAgents(invocationCtx, redTeamClient)
}

func RunRedTeamScanningAgentCreateWorkflow(invocationCtx workflow.InvocationContext, redTeamClient redteamclient.RedTeamClient) ([]workflow.Data, error) {
	if err := commonRedTeamScanningAgentWorkflow(invocationCtx); err != nil {
		return nil, err
	}

	return handleCreateScanningAgent(invocationCtx, redTeamClient)
}

func RunRedTeamScanningAgentDeleteWorkflow(invocationCtx workflow.InvocationContext, redTeamClient redteamclient.RedTeamClient) ([]workflow.Data, error) {
	if err := commonRedTeamScanningAgentWorkflow(invocationCtx); err != nil {
		return nil, err
	}

	return handleDeleteScanningAgent(invocationCtx, redTeamClient)
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
	ui := invocationCtx.GetUserInterface()

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

	if err := ui.Output(ScanningAgentConfigMessage(scanningAgentConfig.FarcasterAgentToken, scanningAgentConfig.FarcasterAPIURL)); err != nil {
		logger.Debug().Err(err).Msg("error while outputting scanning agent config message")
	}

	agentBytes, err := json.Marshal(scanningAgent)
	if err != nil {
		logger.Debug().Err(err).Msg("error while marshaling scanning agent")
		return nil, redteam_errors.NewGenericRedTeamError("Failed processing scanning agent", err)
	}

	workflowData := []workflow.Data{
		newWorkflowData(scanningAgentCreateWorkflowType, "application/json", agentBytes),
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

	validate := validator.New()
	if clientConfigErr := validate.Var(scanningAgentID, "uuid"); clientConfigErr != nil {
		return nil, redteam_errors.NewBadRequestError(fmt.Sprintf("Scanning agent ID is not a valid UUID: %q", scanningAgentID))
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

	workflowData := newWorkflowData(scanningAgentDeleteWorkflowType, "application/json", resultsBytes)
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

	workflowData := newWorkflowData(scanningAgentWorkflowType, "application/json", resultsBytes)
	return []workflow.Data{workflowData}, nil
}

//nolint:ireturn // Unable to change return type of external library
func newWorkflowData(id workflow.Identifier, contentType string, data []byte) workflow.Data {
	return workflow.NewData(
		id,
		contentType,
		data,
	)
}
