package redteamget

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-playground/validator/v10"
	cli_errors "github.com/snyk/error-catalog-golang-public/cli"
	snyk_common_errors "github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"

	redteam_errors "github.com/snyk/cli-extension-ai-bom/internal/errors/redteam"
	redteamclient "github.com/snyk/cli-extension-ai-bom/internal/services/red-team-client"
	"github.com/snyk/cli-extension-ai-bom/internal/utils"
)

const (
	getWorkflowName = "redteam.get"
	userAgent       = "cli-extension-ai-bom-redteam-get"
)

var (
	getWorkflowID   = workflow.NewWorkflowIdentifier(getWorkflowName)
	getWorkflowType = workflow.NewTypeIdentifier(getWorkflowID, getWorkflowName)
)

func RegisterRedTeamGetWorkflow(e workflow.Engine) error {
	flagset := pflag.NewFlagSet("snyk-cli-extension-ai-bom-redteam-get", pflag.ExitOnError)
	flagset.Bool(utils.FlagExperimental, false, "This is an experimental feature that will contain breaking changes in future revisions")
	flagset.String(utils.FlagScanningAgentID, "", "Scan ID to retrieve results for")

	configuration := workflow.ConfigurationOptionsFromFlagset(flagset)
	if _, err := e.Register(getWorkflowID, configuration, redTeamGetWorkflow); err != nil {
		return fmt.Errorf("error while registering red team get workflow: %w", err)
	}
	return nil
}

func getRedTeamClient(invocationCtx workflow.InvocationContext) *redteamclient.ClientImpl {
	logger := invocationCtx.GetEnhancedLogger()
	config := invocationCtx.GetConfiguration()
	baseAPIURL := config.GetString(configuration.API_URL)
	return redteamclient.NewRedTeamClient(logger, invocationCtx.GetNetworkAccess().GetHttpClient(), userAgent, baseAPIURL)
}

func redTeamGetWorkflow(invocationCtx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	return RunRedTeamGetWorkflow(invocationCtx, getRedTeamClient(invocationCtx))
}

func RunRedTeamGetWorkflow(
	invocationCtx workflow.InvocationContext,
	redTeamClient redteamclient.RedTeamClient,
) ([]workflow.Data, error) {
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
		return nil, snyk_common_errors.NewUnauthorisedError("")
	}

	return handleGetScanResults(invocationCtx, redTeamClient)
}

func handleGetScanResults(
	invocationCtx workflow.InvocationContext,
	redTeamClient redteamclient.RedTeamClient,
) ([]workflow.Data, error) {
	logger := invocationCtx.GetEnhancedLogger()
	config := invocationCtx.GetConfiguration()
	ctx := context.Background()

	orgID := config.GetString(configuration.ORGANIZATION)

	scanID := config.GetString(utils.FlagScanningAgentID)
	if scanID == "" {
		return nil, redteam_errors.NewBadRequestError("No scan ID specified")
	}

	validate := validator.New()
	if err := validate.Var(scanID, "uuid"); err != nil {
		return nil, redteam_errors.NewBadRequestError(fmt.Sprintf("Scan ID is not a valid UUID: %q", scanID))
	}

	logger.Debug().Str("scanID", scanID).Msg("Fetching scan results")

	results, rtErr := redTeamClient.GetScanResults(ctx, orgID, scanID)
	if rtErr != nil {
		logger.Debug().Err(rtErr).Msg("Error fetching scan results")
		return nil, rtErr
	}

	logger.Debug().Msgf("Retrieved scan results for scan ID: %s", scanID)

	resultsBytes, err := json.Marshal(results)
	if err != nil {
		logger.Debug().Err(err).Msg("Error marshaling scan results")
		return nil, redteam_errors.NewGenericRedTeamError("Failed processing scan results", err)
	}

	workflowData := newWorkflowData(getWorkflowType, "application/json", resultsBytes)
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
