package aibomcreate_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/cli-extension-ai-bom/internal/commands/aibomcreate"
	"github.com/snyk/cli-extension-ai-bom/internal/utils"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	errors "github.com/snyk/cli-extension-ai-bom/internal/errors"
	"github.com/snyk/cli-extension-ai-bom/mocks/aibomclientmock"
	"github.com/snyk/cli-extension-ai-bom/mocks/fileuploadmock"
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
	aiBomClient := aibomclientmock.NewMockAiBomClient(ctrl)
	uploadRevisionID := uuid.New()
	fileUploadClient := fileuploadmock.NewMockClient(ctrl)

	fileUploadClient.EXPECT().CreateRevisionFromChan(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(fileupload.UploadResult{
		RevisionID: uploadRevisionID,
	}, nil)

	aiBomClient.EXPECT().
		GenerateAIBOM(gomock.Any(), gomock.Any(), uploadRevisionID).Times(1).Return(exampleAIBOM, nil)
	aiBomClient.EXPECT().CheckAPIAvailability(gomock.Any(), gomock.Any()).Times(1).Return(nil)

	workflowData, err := aibomcreate.RunAiBomWorkflow(ictx, frameworkmock.MockOrgID, aiBomClient, fileUploadClient)
	assert.Nil(t, err)
	assert.Len(t, workflowData, 1)
	aiBom := workflowData[0].GetPayload()
	actual, ok := aiBom.([]byte)
	assert.True(t, ok)
	assert.Equal(t, exampleAIBOM, string(actual))
}

func TestAiBomWorkflow_Upload_HAPPY(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ctrl := gomock.NewController(t)
	cfg := ictx.GetConfiguration()
	cfg.Set(utils.FlagExperimental, true)
	cfg.Set(utils.FlagUpload, true)
	cfg.Set(utils.FlagRepoName, "repo-name")
	aiBomClient := aibomclientmock.NewMockAiBomClient(ctrl)
	uploadRevisionID := uuid.New()
	fileUploadClient := fileuploadmock.NewMockClient(ctrl)

	fileUploadClient.EXPECT().CreateRevisionFromChan(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(fileupload.UploadResult{
		RevisionID: uploadRevisionID,
	}, nil)

	checkAPIAvailablilityCall := aiBomClient.EXPECT().CheckAPIAvailability(gomock.Any(), frameworkmock.MockOrgID).Times(1).Return(nil)

	aiBomClient.EXPECT().
		CreateAndUploadAIBOM(gomock.Any(), frameworkmock.MockOrgID, uploadRevisionID, "repo-name").Times(1).Return(exampleAIBOM, nil).After(checkAPIAvailablilityCall)

	workflowData, err := aibomcreate.RunAiBomWorkflow(ictx, frameworkmock.MockOrgID, aiBomClient, fileUploadClient)
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
	aiBomClient := aibomclientmock.NewMockAiBomClient(ctrl)
	uploadRevisionID := uuid.New()
	fileUploadClient := fileuploadmock.NewMockClient(ctrl)

	fileUploadClient.EXPECT().CreateRevisionFromChan(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(fileupload.UploadResult{
		RevisionID: uploadRevisionID,
	}, nil)

	aiBomClient.EXPECT().CheckAPIAvailability(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	aiBomClient.EXPECT().
		GenerateAIBOM(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(exampleAIBOM, nil)

	workflowData, err := aibomcreate.RunAiBomWorkflow(ictx, frameworkmock.MockOrgID, aiBomClient, fileUploadClient)
	assert.Nil(t, err)
	assert.Len(t, workflowData, 1)
	aiBom := workflowData[0].GetPayload()
	actual, ok := aiBom.([]byte)
	assert.True(t, ok)
	assert.Contains(t, string(actual), "<!DOCTYPE html>")
	assert.Contains(t, string(actual), exampleAIBOM)
}

func TestAiBomWorkflow_APIUnavailable(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ctrl := gomock.NewController(t)
	ictx.GetConfiguration().Set(utils.FlagExperimental, true)
	aiBomClient := aibomclientmock.NewMockAiBomClient(ctrl)
	unavailableError := errors.NewInternalError("unavailable")
	fileUploadClient := fileuploadmock.NewMockClient(ctrl)

	aiBomClient.EXPECT().CheckAPIAvailability(gomock.Any(), gomock.Any()).Times(1).Return(unavailableError)

	_, err := aibomcreate.RunAiBomWorkflow(ictx, frameworkmock.MockOrgID, aiBomClient, fileUploadClient)
	assert.Equal(t, unavailableError.SnykError, err)
}

func TestAiBomWorkflow_UPLOAD_BUNDLE_FAIL(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(utils.FlagExperimental, true)
	ctrl := gomock.NewController(t)
	aiBomClient := aibomclientmock.NewMockAiBomClient(ctrl)
	uploadRevisionID := uuid.New()
	fileUploadClient := fileuploadmock.NewMockClient(ctrl)
	uploadErr := errors.NewInternalError("Upload error")

	fileUploadClient.EXPECT().CreateRevisionFromChan(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(fileupload.UploadResult{
		RevisionID: uploadRevisionID,
	}, uploadErr)

	aiBomClient.EXPECT().CheckAPIAvailability(gomock.Any(), gomock.Any()).Times(1).Return(nil)

	_, err := aibomcreate.RunAiBomWorkflow(ictx, frameworkmock.MockOrgID, aiBomClient, fileUploadClient)
	assert.Equal(t, uploadErr.SnykError, err)
}

func TestAiBomWorkflow_AIBOM_GENERATION_FAIL(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(utils.FlagExperimental, true)
	ctrl := gomock.NewController(t)
	aiBomClient := aibomclientmock.NewMockAiBomClient(ctrl)
	aiBomErr := errors.NewInternalError("Test error")
	uploadRevisionID := uuid.New()
	fileUploadClient := fileuploadmock.NewMockClient(ctrl)

	fileUploadClient.EXPECT().CreateRevisionFromChan(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(fileupload.UploadResult{
		RevisionID: uploadRevisionID,
	}, nil)

	aiBomClient.EXPECT().CheckAPIAvailability(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	aiBomClient.EXPECT().
		GenerateAIBOM(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return("", aiBomErr)

	_, err := aibomcreate.RunAiBomWorkflow(ictx, frameworkmock.MockOrgID, aiBomClient, fileUploadClient)
	assert.Equal(t, aiBomErr.SnykError, err)
}

func TestAiBomWorkflow_NO_EXPERIMENTAL(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ctrl := gomock.NewController(t)
	aiBomClient := aibomclientmock.NewMockAiBomClient(ctrl)
	fileUploadClient := fileuploadmock.NewMockClient(ctrl)

	_, err := aibomcreate.RunAiBomWorkflow(ictx, frameworkmock.MockOrgID, aiBomClient, fileUploadClient)
	assert.EqualError(t, err, "Command is experimental")
}

func TestAiBomWorkflow_UNAUTHORIZED(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ctrl := gomock.NewController(t)
	aiBomClient := aibomclientmock.NewMockAiBomClient(ctrl)
	fileUploadClient := fileuploadmock.NewMockClient(ctrl)

	ictx.GetConfiguration().Set(utils.FlagExperimental, true)

	// Unauthorized either won't have an orgId
	ictx.GetConfiguration().Set(configuration.ORGANIZATION, "")
	_, err := aibomcreate.AiBomWorkflow(ictx, nil)
	assert.EqualError(t, err, "Authentication error")

	// Or, Unauthorized users that provide an explicit orgId will be handled by the api availability check
	ictx.GetConfiguration().Set(configuration.ORGANIZATION, "5ffb5f8b-8cd3-4cfc-bce6-d23d19d4fa11")
	aiBomClient.EXPECT().CheckAPIAvailability(gomock.Any(), gomock.Any()).Times(1).
		Return(errors.NewUnauthorizedError(""))
	_, err = aibomcreate.RunAiBomWorkflow(ictx, frameworkmock.MockOrgID, aiBomClient, fileUploadClient)
	assert.EqualError(t, err, "Authentication error")
}
