package aibomcreate_test

import (
	"fmt"
	"io"
	"log"
	"testing"

	libGoMock "github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"

	"github.com/snyk/cli-extension-ai-bom/internal/commands/aibomcreate"
	"github.com/snyk/cli-extension-ai-bom/internal/flags"

	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/stretchr/testify/assert"
	gomock "go.uber.org/mock/gomock"

	"github.com/snyk/cli-extension-ai-bom/internal/services/code"
	codeMock "github.com/snyk/cli-extension-ai-bom/internal/services/code/mock"
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
	ictx := mockInvocationContext(t)
	ctrl := gomock.NewController(t)
	ictx.GetConfiguration().Set(flags.FlagExperimental, true)
	mockCodeService := codeMock.NewMockCodeService(ctrl)

	sarif := code.Sarif{Runs: []code.SarifRun{{Results: []code.SarifResult{{Message: code.SarifMessage{Text: exampleAIBOM}}}}}}
	mockCodeService.EXPECT().Analyze(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).
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
	ictx := mockInvocationContext(t)
	ictx.GetConfiguration().Set(flags.FlagExperimental, true)
	ctrl := gomock.NewController(t)
	mockCodeService := codeMock.NewMockCodeService(ctrl)

	mockCodeService.EXPECT().Analyze(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).
		Return(nil, nil, fmt.Errorf("test error"))

	_, err := aibomcreate.RunAiBomWorkflow(ictx, mockCodeService)
	assert.EqualError(t, err, "code client failed to analyze bundle: test error")
}

func TestAiBomWorkflow_NO_EXPERIMENTAL(t *testing.T) {
	ictx := mockInvocationContext(t)
	ctrl := gomock.NewController(t)
	mockCodeService := codeMock.NewMockCodeService(ctrl)

	_, err := aibomcreate.RunAiBomWorkflow(ictx, mockCodeService)
	assert.EqualError(t, err, "Flag `--experimental` is required to execute this command.")
}

func mockInvocationContext(
	t *testing.T,
) *mocks.MockInvocationContext {
	t.Helper()
	ctrl := libGoMock.NewController(t)

	mockConfig := configuration.New()
	mockConfig.Set(configuration.AUTHENTICATION_TOKEN, "<SOME API TOKEN>")
	mockConfig.Set(configuration.ORGANIZATION, "6277734c-fc84-4c74-9662-33d46ec66c53")
	mockConfig.Set("format", "cyclonedx1.4+json")
	mockConfig.Set("name", "goof")
	mockConfig.Set("version", "0.0.0")

	mockRuntimeInfo := runtimeinfo.New(
		runtimeinfo.WithName("test-app"),
		runtimeinfo.WithVersion("1.2.3"))

	enhancedLogger := zerolog.New(io.Discard)
	ictx := mocks.NewMockInvocationContext(ctrl)
	ictx.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()
	ictx.EXPECT().GetEngine().Return(nil).AnyTimes()
	ictx.EXPECT().GetNetworkAccess().Return(networking.NewNetworkAccess(mockConfig)).AnyTimes()
	ictx.EXPECT().GetLogger().Return(log.New(io.Discard, "", 0)).AnyTimes()
	ictx.EXPECT().GetEnhancedLogger().Return(&enhancedLogger).AnyTimes()
	ictx.EXPECT().GetRuntimeInfo().Return(mockRuntimeInfo).AnyTimes()
	ictx.EXPECT().GetUserInterface().Return(nil).AnyTimes()
	return ictx
}
