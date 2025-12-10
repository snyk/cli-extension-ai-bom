package redteamscanningagent_test

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/snyk/cli-extension-ai-bom/internal/commands/redteamscanningagent"
	redteamclientmock "github.com/snyk/cli-extension-ai-bom/internal/services/red-team-client/mock"
	"github.com/snyk/cli-extension-ai-bom/mocks/frameworkmock"
)

const (
	experimentalKey = "experimental"
	testOrgID       = "test-org"
)

func TestRunRedTeamScanningAgentWorkflow_List_HappyPath(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set("organization", testOrgID)

	mockClient := &redteamclientmock.MockRedTeamClient{}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam", "scanning-agent"}
	defer func() { os.Args = originalArgs }()

	results, err := redteamscanningagent.RunRedTeamScanningAgentWorkflow(ictx, mockClient)
	require.NoError(t, err)

	data := make([]map[string]interface{}, 1)
	payload, ok := results[0].GetPayload().([]byte)
	require.True(t, ok)
	err = json.Unmarshal(payload, &data)
	require.NoError(t, err)
	require.Equal(t, 1, len(data))
	require.Equal(t, "test-scanning-agent-id", data[0]["id"])
	require.Equal(t, "test-scanning-agent-name", data[0]["name"])
}

func TestRunRedTeamScanningAgentWorkflow_Create_HappyPath(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set("organization", testOrgID)
	ictx.GetConfiguration().Set("name", "test-scanning-agent-name")

	ui, ok := ictx.GetUserInterface().(*mocks.MockUserInterface)
	require.True(t, ok, "UI should be a mock")
	ui.EXPECT().Output(gomock.Any()).Do(func(output string) {
		require.Contains(t, output, "FARCASTER_AGENT_TOKEN=test-farcaster-agent-token")
		require.Contains(t, output, "FARCASTER_API_URL=test-farcaster-api-url")
	}).Return(nil).Times(1)

	mockClient := &redteamclientmock.MockRedTeamClient{}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam", "scanning-agent", "create", "--name=test-scanning-agent-name"}
	defer func() { os.Args = originalArgs }()

	results, err := redteamscanningagent.RunRedTeamScanningAgentCreateWorkflow(ictx, mockClient)
	require.NoError(t, err)

	require.Len(t, results, 1)

	data := make(map[string]interface{})
	payload, ok := results[0].GetPayload().([]byte)
	require.True(t, ok)
	err = json.Unmarshal(payload, &data)
	require.NoError(t, err)
	require.Equal(t, "test-scanning-agent-id", data["id"])
	require.Equal(t, "test-scanning-agent-name", data["name"])
}

func TestRunRedTeamScanningAgentWorkflow_Delete_HappyPath(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set("organization", testOrgID)
	scanningAgentID := "12345678-90ab-cdef-1234-567890abcdef"
	ictx.GetConfiguration().Set("id", scanningAgentID)

	mockClient := &redteamclientmock.MockRedTeamClient{}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam", "scanning-agent", "delete", fmt.Sprintf("--id=%s", scanningAgentID)}
	defer func() { os.Args = originalArgs }()

	_, err := redteamscanningagent.RunRedTeamScanningAgentDeleteWorkflow(ictx, mockClient)
	require.NoError(t, err)
}

func TestRunRedTeamScanningAgentWorkflow_Delete_MissingID(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(experimentalKey, true)
	ictx.GetConfiguration().Set("organization", testOrgID)

	mockClient := &redteamclientmock.MockRedTeamClient{}

	originalArgs := os.Args
	os.Args = []string{"snyk", "redteam", "scanning-agent", "delete", "--id=test-scanning-agent-id"}
	defer func() { os.Args = originalArgs }()

	_, err := redteamscanningagent.RunRedTeamScanningAgentDeleteWorkflow(ictx, mockClient)
	require.Error(t, err)
	require.Contains(t, err.Error(), "No scanning agent ID")
}
