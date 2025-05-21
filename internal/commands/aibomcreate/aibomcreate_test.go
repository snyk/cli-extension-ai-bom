package aibomcreate_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/snyk/cli-extension-ai-bom/internal/commands/aibomcreate"
	"github.com/snyk/cli-extension-ai-bom/internal/errors"
	"github.com/snyk/cli-extension-ai-bom/internal/utils"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/snyk/cli-extension-ai-bom/internal/services/code"
	"github.com/snyk/cli-extension-ai-bom/internal/services/depgraph"
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

	depgraphResult := depgraph.DepgraphResult{
		DepgraphBytes: []json.RawMessage{
			json.RawMessage(`{"foo": "bar"}`),
		},
	}
	mockDepgraphService.EXPECT().GetDepgraph(gomock.Any()).Times(1).Return(&depgraphResult, nil)
	sarif := code.Sarif{Runs: []code.SarifRun{{Results: []code.SarifResult{{Message: code.SarifMessage{Text: exampleAIBOM}}}}}}
	depGraphMap := map[string][]byte{"/_0.snykdepgraph": depgraphResult.DepgraphBytes[0]}
	mockCodeService.EXPECT().Analyze(gomock.Any(), depGraphMap, gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).
		Return(&code.AnalysisResponse{Sarif: sarif}, nil, nil)

	workflowData, err := aibomcreate.RunAiBomWorkflow(ictx, mockCodeService, mockDepgraphService)
	assert.Nil(t, err)
	assert.Len(t, workflowData, 1)
	aiBom := workflowData[0].GetPayload()
	actual, ok := aiBom.([]byte)
	assert.True(t, ok)
	assert.Equal(t, exampleAIBOM, string(actual))
}

func TestAiBomWorkflow_DEPGRAPH_FAIL(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ctrl := gomock.NewController(t)
	ictx.GetConfiguration().Set(utils.FlagExperimental, true)
	mockCodeService := codemock.NewMockCodeService(ctrl)
	mockDepgraphService := depgraphmock.NewMockDepgraphService(ctrl)

	mockDepgraphService.EXPECT().GetDepgraph(gomock.Any()).Times(1).Return(nil, fmt.Errorf("depgraphs error"))
	sarif := code.Sarif{Runs: []code.SarifRun{{Results: []code.SarifResult{{Message: code.SarifMessage{Text: exampleAIBOM}}}}}}
	// Analysis should still work even if we can't fetch depgraphs
	mockCodeService.EXPECT().Analyze(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).
		Return(&code.AnalysisResponse{Sarif: sarif}, nil, nil)

	workflowData, err := aibomcreate.RunAiBomWorkflow(ictx, mockCodeService, mockDepgraphService)
	assert.Nil(t, err)
	assert.Len(t, workflowData, 1)
	aiBom := workflowData[0].GetPayload()
	actual, ok := aiBom.([]byte)
	assert.True(t, ok)
	assert.Equal(t, exampleAIBOM, string(actual))
}

func TestAiBomWorkflow_ANALYSIS_FAIL(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(utils.FlagExperimental, true)
	ctrl := gomock.NewController(t)
	mockCodeService := codemock.NewMockCodeService(ctrl)
	mockDepgraphService := depgraphmock.NewMockDepgraphService(ctrl)

	codeErr := errors.NewInternalError("Failed to upload file bundle")
	mockDepgraphService.EXPECT().GetDepgraph(gomock.Any()).Times(1).Return(&depgraph.DepgraphResult{}, nil)
	mockCodeService.EXPECT().Analyze(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).
		Return(nil, nil, codeErr)

	_, err := aibomcreate.RunAiBomWorkflow(ictx, mockCodeService, mockDepgraphService)
	assert.Equal(t, codeErr.SnykError, err)
}

func TestAiBomWorkflow_NO_EXPERIMENTAL(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ctrl := gomock.NewController(t)
	mockCodeService := codemock.NewMockCodeService(ctrl)
	mockDepgraphService := depgraphmock.NewMockDepgraphService(ctrl)

	_, err := aibomcreate.RunAiBomWorkflow(ictx, mockCodeService, mockDepgraphService)
	assert.EqualError(t, err, "Command is experimental")
}
