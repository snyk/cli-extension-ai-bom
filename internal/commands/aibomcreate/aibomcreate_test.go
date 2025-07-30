package aibomcreate_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/snyk/cli-extension-ai-bom/internal/commands/aibomcreate"
	"github.com/snyk/cli-extension-ai-bom/internal/utils"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	errors "github.com/snyk/cli-extension-ai-bom/internal/errors"
	"github.com/snyk/cli-extension-ai-bom/internal/services/depgraph"
	"github.com/snyk/cli-extension-ai-bom/mocks/aibomclientmock"
	"github.com/snyk/cli-extension-ai-bom/mocks/codemock"
	"github.com/snyk/cli-extension-ai-bom/mocks/depgraphmock"
	"github.com/snyk/cli-extension-ai-bom/mocks/frameworkmock"
)

var exampleAIBOM = `{
   "$schema" : "https://cyclonedx.org/schema/bom-1.6.schema.json",
   "bomFormat" : "CycloneDX",
   "components" : [
      {
         "bom-ref" : "application:Root",
         "name" : "Root",
         "type" : "application"
      }
   ],
   "specVersion" : "1.6",
   "version" : 1
}`

func TestAiBomWorkflow_HAPPY(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ctrl := gomock.NewController(t)
	ictx.GetConfiguration().Set(utils.FlagExperimental, true)
	mockCodeService := codemock.NewMockCodeService(ctrl)
	mockDepgraphService := depgraphmock.NewMockDepgraphService(ctrl)
	aiBomClient := aibomclientmock.NewMockAiBomClient(ctrl)

	depgraphResult := depgraph.DepgraphResult{
		DepgraphBytes: []json.RawMessage{
			json.RawMessage(`{"foo": "bar"}`),
		},
	}
	mockDepgraphService.EXPECT().GetDepgraph(gomock.Any()).Times(1).Return(&depgraphResult, nil)
	depGraphMap := map[string][]byte{"/_0.snykdepgraph": depgraphResult.DepgraphBytes[0]}
	mockCodeService.EXPECT().UploadBundle(gomock.Any(), depGraphMap, gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).
		Return("bundle-id", nil)
	aiBomClient.EXPECT().
		GenerateAIBOM(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(exampleAIBOM, nil)
	aiBomClient.EXPECT().CheckAPIAvailability(gomock.Any(), gomock.Any()).Times(1).Return(nil)

	workflowData, err := aibomcreate.RunAiBomWorkflow(ictx, mockCodeService, mockDepgraphService, aiBomClient)
	assert.Nil(t, err)
	assert.Len(t, workflowData, 1)
	aiBom := workflowData[0].GetPayload()
	actual, ok := aiBom.([]byte)
	assert.True(t, ok)
	assert.Equal(t, exampleAIBOM, string(actual))
}

func TestAiBomWorkflow_HTML(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ctrl := gomock.NewController(t)
	ictx.GetConfiguration().Set(utils.FlagExperimental, true)
	ictx.GetConfiguration().Set(utils.FlagHTML, true)
	mockCodeService := codemock.NewMockCodeService(ctrl)
	mockDepgraphService := depgraphmock.NewMockDepgraphService(ctrl)
	aiBomClient := aibomclientmock.NewMockAiBomClient(ctrl)

	mockDepgraphService.EXPECT().GetDepgraph(gomock.Any()).Times(1).Return(&depgraph.DepgraphResult{}, nil)
	mockCodeService.EXPECT().UploadBundle(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).
		Return("bundle-id", nil)
	aiBomClient.EXPECT().CheckAPIAvailability(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	aiBomClient.EXPECT().
		GenerateAIBOM(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(exampleAIBOM, nil)

	workflowData, err := aibomcreate.RunAiBomWorkflow(ictx, mockCodeService, mockDepgraphService, aiBomClient)
	assert.Nil(t, err)
	assert.Len(t, workflowData, 1)
	aiBom := workflowData[0].GetPayload()
	actual, ok := aiBom.([]byte)
	assert.True(t, ok)
	assert.Contains(t, string(actual), "<!DOCTYPE html>")
	assert.Contains(t, string(actual), exampleAIBOM)
}

func TestAiBomWorkflow_DEPGRAPH_FAIL(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ctrl := gomock.NewController(t)
	ictx.GetConfiguration().Set(utils.FlagExperimental, true)
	mockCodeService := codemock.NewMockCodeService(ctrl)
	mockDepgraphService := depgraphmock.NewMockDepgraphService(ctrl)
	aiBomClient := aibomclientmock.NewMockAiBomClient(ctrl)

	mockDepgraphService.EXPECT().GetDepgraph(gomock.Any()).Times(1).Return(nil, fmt.Errorf("depgraphs error"))
	mockCodeService.EXPECT().UploadBundle(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).
		Return("bundle-id", nil)
	aiBomClient.EXPECT().CheckAPIAvailability(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	aiBomClient.EXPECT().
		GenerateAIBOM(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(exampleAIBOM, nil)

	workflowData, err := aibomcreate.RunAiBomWorkflow(ictx, mockCodeService, mockDepgraphService, aiBomClient)
	assert.Nil(t, err)
	assert.Len(t, workflowData, 1)
	aiBom := workflowData[0].GetPayload()
	actual, ok := aiBom.([]byte)
	assert.True(t, ok)
	assert.Equal(t, exampleAIBOM, string(actual))
}

func TestAiBomWorkflow_APIUnavailable(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ctrl := gomock.NewController(t)
	ictx.GetConfiguration().Set(utils.FlagExperimental, true)
	mockCodeService := codemock.NewMockCodeService(ctrl)
	mockDepgraphService := depgraphmock.NewMockDepgraphService(ctrl)
	aiBomClient := aibomclientmock.NewMockAiBomClient(ctrl)
	unavailableError := errors.NewInternalError("unavailable")
	aiBomClient.EXPECT().CheckAPIAvailability(gomock.Any(), gomock.Any()).Times(1).Return(unavailableError)

	_, err := aibomcreate.RunAiBomWorkflow(ictx, mockCodeService, mockDepgraphService, aiBomClient)
	assert.Equal(t, unavailableError.SnykError, err)
}

func TestAiBomWorkflow_UPLOAD_BUNDLE_FAIL(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(utils.FlagExperimental, true)
	ctrl := gomock.NewController(t)
	mockCodeService := codemock.NewMockCodeService(ctrl)
	mockDepgraphService := depgraphmock.NewMockDepgraphService(ctrl)
	aiBomClient := aibomclientmock.NewMockAiBomClient(ctrl)
	uploadErr := errors.NewInternalError("Upload error")
	mockDepgraphService.EXPECT().GetDepgraph(gomock.Any()).Times(1).Return(&depgraph.DepgraphResult{}, nil)
	mockCodeService.EXPECT().UploadBundle(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).
		Return("", uploadErr)
	aiBomClient.EXPECT().CheckAPIAvailability(gomock.Any(), gomock.Any()).Times(1).Return(nil)

	_, err := aibomcreate.RunAiBomWorkflow(ictx, mockCodeService, mockDepgraphService, aiBomClient)
	assert.Equal(t, uploadErr.SnykError, err)
}

func TestAiBomWorkflow_AIBOM_GENERATION_FAIL(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(utils.FlagExperimental, true)
	ctrl := gomock.NewController(t)
	mockCodeService := codemock.NewMockCodeService(ctrl)
	mockDepgraphService := depgraphmock.NewMockDepgraphService(ctrl)
	aiBomClient := aibomclientmock.NewMockAiBomClient(ctrl)
	aiBomErr := errors.NewInternalError("Test error")
	mockDepgraphService.EXPECT().GetDepgraph(gomock.Any()).Times(1).Return(&depgraph.DepgraphResult{}, nil)
	mockCodeService.EXPECT().UploadBundle(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).
		Return("bundle-id", nil)
	aiBomClient.EXPECT().CheckAPIAvailability(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	aiBomClient.EXPECT().
		GenerateAIBOM(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return("", aiBomErr)

	_, err := aibomcreate.RunAiBomWorkflow(ictx, mockCodeService, mockDepgraphService, aiBomClient)
	assert.Equal(t, aiBomErr.SnykError, err)
}

func TestAiBomWorkflow_NO_EXPERIMENTAL(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ctrl := gomock.NewController(t)
	mockCodeService := codemock.NewMockCodeService(ctrl)
	mockDepgraphService := depgraphmock.NewMockDepgraphService(ctrl)
	aiBomClient := aibomclientmock.NewMockAiBomClient(ctrl)

	_, err := aibomcreate.RunAiBomWorkflow(ictx, mockCodeService, mockDepgraphService, aiBomClient)
	assert.EqualError(t, err, "Command is experimental")
}
