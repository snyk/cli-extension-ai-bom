package aibomcreate_test

import (
	"testing"

	"github.com/snyk/cli-extension-ai-bom/internal/commands/aibomcreate"
	"github.com/snyk/cli-extension-ai-bom/internal/errors"
	"github.com/snyk/cli-extension-ai-bom/internal/utils"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/snyk/cli-extension-ai-bom/internal/services/code"
	"github.com/snyk/cli-extension-ai-bom/mocks/codemock"
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

	sarif := code.Sarif{Runs: []code.SarifRun{{Results: []code.SarifResult{{Message: code.SarifMessage{Text: exampleAIBOM}}}}}}
	mockCodeService.EXPECT().Analyze(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).
		Return(&code.AnalysisResponse{Sarif: sarif}, nil, nil)

	workflowData, err := aibomcreate.RunAiBomWorkflow(ictx, mockCodeService)
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

	codeErr := errors.NewInternalError("failed to upload file bundle")
	mockCodeService.EXPECT().Analyze(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).
		Return(nil, nil, codeErr)

	_, err := aibomcreate.RunAiBomWorkflow(ictx, mockCodeService)
	assert.Equal(t, codeErr.SnykError, err)
}

func TestAiBomWorkflow_NO_EXPERIMENTAL(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ctrl := gomock.NewController(t)
	mockCodeService := codemock.NewMockCodeService(ctrl)

	_, err := aibomcreate.RunAiBomWorkflow(ictx, mockCodeService)
	assert.EqualError(t, err, "Command is experimental")
}
