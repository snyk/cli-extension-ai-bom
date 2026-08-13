package aibomcreate_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	git "github.com/go-git/go-git/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	"github.com/snyk/go-application-framework/pkg/configuration"
	frameworkUtils "github.com/snyk/go-application-framework/pkg/utils"

	"github.com/snyk/cli-extension-ai-bom/internal/commands/aibomcreate"
	"github.com/snyk/cli-extension-ai-bom/internal/utils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	errors "github.com/snyk/cli-extension-ai-bom/internal/errors"
	"github.com/snyk/cli-extension-ai-bom/mocks/aibomclientmock"
	"github.com/snyk/cli-extension-ai-bom/mocks/fileuploadmock"
	"github.com/snyk/cli-extension-ai-bom/mocks/frameworkmock"
)

const testAIBOMID = "test-aibom-id"

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
	aiBomClient := aibomclientmock.NewMockAiBomClient(ctrl)
	uploadRevisionID := uuid.New()
	fileUploadClient := fileuploadmock.NewMockClient(ctrl)

	fileUploadClient.EXPECT().CreateRevisionFromChan(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(fileupload.UploadResult{
		RevisionID: uploadRevisionID,
	}, nil)

	aiBomClient.EXPECT().
		GenerateAIBOM(gomock.Any(), gomock.Any(), uploadRevisionID, false).Times(1).Return(exampleAIBOM, testAIBOMID, nil)
	aiBomClient.EXPECT().CheckAPIAvailability(gomock.Any(), gomock.Any()).Times(1).Return(nil)

	workflowData, err := aibomcreate.RunAiBomWorkflow(ictx, frameworkmock.MockOrgID, aiBomClient, fileUploadClient, false)
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
		CreateAndUploadAIBOM(gomock.Any(), frameworkmock.MockOrgID, uploadRevisionID, "repo-name", false).
		Times(1).
		Return(exampleAIBOM, testAIBOMID, nil).
		After(checkAPIAvailablilityCall)

	workflowData, err := aibomcreate.RunAiBomWorkflow(ictx, frameworkmock.MockOrgID, aiBomClient, fileUploadClient, false)
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
	ictx.GetConfiguration().Set(utils.FlagHTML, true)
	aiBomClient := aibomclientmock.NewMockAiBomClient(ctrl)
	uploadRevisionID := uuid.New()
	fileUploadClient := fileuploadmock.NewMockClient(ctrl)

	fileUploadClient.EXPECT().CreateRevisionFromChan(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(fileupload.UploadResult{
		RevisionID: uploadRevisionID,
	}, nil)

	aiBomClient.EXPECT().CheckAPIAvailability(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	aiBomClient.EXPECT().
		GenerateAIBOM(gomock.Any(), gomock.Any(), gomock.Any(), false).Times(1).Return(exampleAIBOM, testAIBOMID, nil)

	workflowData, err := aibomcreate.RunAiBomWorkflow(ictx, frameworkmock.MockOrgID, aiBomClient, fileUploadClient, false)
	assert.Nil(t, err)
	assert.Len(t, workflowData, 1)
	aiBom := workflowData[0].GetPayload()
	actual, ok := aiBom.([]byte)
	assert.True(t, ok)
	assert.Contains(t, string(actual), "<!DOCTYPE html>")
	assert.Contains(t, string(actual), exampleAIBOM)
}

func TestAiBomWorkflow_Enriched_HAPPY(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ctrl := gomock.NewController(t)
	cfg := ictx.GetConfiguration()
	cfg.Set(utils.FlagEnriched, true)
	aiBomClient := aibomclientmock.NewMockAiBomClient(ctrl)
	uploadRevisionID := uuid.New()
	fileUploadClient := fileuploadmock.NewMockClient(ctrl)

	fileUploadClient.EXPECT().CreateRevisionFromChan(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(fileupload.UploadResult{
		RevisionID: uploadRevisionID,
	}, nil)

	aiBomClient.EXPECT().CheckAPIAvailability(gomock.Any(), gomock.Any()).Times(1).Return(nil)
	aiBomClient.EXPECT().
		GenerateAIBOM(gomock.Any(), gomock.Any(), uploadRevisionID, true).Times(1).Return(exampleAIBOM, testAIBOMID, nil)

	workflowData, err := aibomcreate.RunAiBomWorkflow(ictx, frameworkmock.MockOrgID, aiBomClient, fileUploadClient, false)
	assert.Nil(t, err)
	assert.Len(t, workflowData, 1)
}

func TestAiBomWorkflow_Enriched_Upload_HAPPY(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ctrl := gomock.NewController(t)
	cfg := ictx.GetConfiguration()
	cfg.Set(utils.FlagUpload, true)
	cfg.Set(utils.FlagRepoName, "repo-name")
	cfg.Set(utils.FlagEnriched, true)
	aiBomClient := aibomclientmock.NewMockAiBomClient(ctrl)
	uploadRevisionID := uuid.New()
	fileUploadClient := fileuploadmock.NewMockClient(ctrl)

	fileUploadClient.EXPECT().CreateRevisionFromChan(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(fileupload.UploadResult{
		RevisionID: uploadRevisionID,
	}, nil)

	aiBomClient.EXPECT().CheckAPIAvailability(gomock.Any(), frameworkmock.MockOrgID).Times(1).Return(nil)
	aiBomClient.EXPECT().
		CreateAndUploadAIBOM(gomock.Any(), frameworkmock.MockOrgID, uploadRevisionID, "repo-name", true).
		Times(1).
		Return(exampleAIBOM, testAIBOMID, nil)

	workflowData, err := aibomcreate.RunAiBomWorkflow(ictx, frameworkmock.MockOrgID, aiBomClient, fileUploadClient, false)
	assert.Nil(t, err)
	assert.Len(t, workflowData, 1)
}

func TestAiBomWorkflow_APIUnavailable(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ctrl := gomock.NewController(t)
	aiBomClient := aibomclientmock.NewMockAiBomClient(ctrl)
	unavailableError := errors.NewInternalError("unavailable")
	fileUploadClient := fileuploadmock.NewMockClient(ctrl)

	aiBomClient.EXPECT().CheckAPIAvailability(gomock.Any(), gomock.Any()).Times(1).Return(unavailableError)

	_, err := aibomcreate.RunAiBomWorkflow(ictx, frameworkmock.MockOrgID, aiBomClient, fileUploadClient, false)
	assert.Equal(t, unavailableError.SnykError, err)
}

func TestAiBomWorkflow_UPLOAD_BUNDLE_FAIL(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ctrl := gomock.NewController(t)
	aiBomClient := aibomclientmock.NewMockAiBomClient(ctrl)
	uploadRevisionID := uuid.New()
	fileUploadClient := fileuploadmock.NewMockClient(ctrl)
	uploadErr := fmt.Errorf("upload error")

	fileUploadClient.EXPECT().CreateRevisionFromChan(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(fileupload.UploadResult{
		RevisionID: uploadRevisionID,
	}, uploadErr)

	aiBomClient.EXPECT().CheckAPIAvailability(gomock.Any(), gomock.Any()).Times(1).Return(nil)

	_, err := aibomcreate.RunAiBomWorkflow(ictx, frameworkmock.MockOrgID, aiBomClient, fileUploadClient, false)
	assert.Equal(t, fmt.Errorf("failed to create upload revision: %w", uploadErr), err)
}

func TestAiBomWorkflow_NO_SUPPORTED_FILES(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ctrl := gomock.NewController(t)
	aiBomClient := aibomclientmock.NewMockAiBomClient(ctrl)
	uploadRevisionID := uuid.New()
	fileUploadClient := fileuploadmock.NewMockClient(ctrl)

	fileUploadClient.EXPECT().CreateRevisionFromChan(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(fileupload.UploadResult{
		RevisionID: uploadRevisionID,
	}, fileupload.ErrNoFilesProvided)

	aiBomClient.EXPECT().CheckAPIAvailability(gomock.Any(), gomock.Any()).Times(1).Return(nil)

	_, err := aibomcreate.RunAiBomWorkflow(ictx, frameworkmock.MockOrgID, aiBomClient, fileUploadClient, false)
	assert.Equal(t, errors.NewNoSupportedFilesError().SnykError.Error(), err.Error())
}

func TestAiBomWorkflow_AIBOM_GENERATION_FAIL(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
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
		GenerateAIBOM(gomock.Any(), gomock.Any(), gomock.Any(), false).Times(1).Return("", "", aiBomErr)

	_, err := aibomcreate.RunAiBomWorkflow(ictx, frameworkmock.MockOrgID, aiBomClient, fileUploadClient, false)
	assert.Equal(t, aiBomErr.SnykError, err)
}

func TestAiBomWorkflow_UNAUTHORIZED(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ctrl := gomock.NewController(t)
	aiBomClient := aibomclientmock.NewMockAiBomClient(ctrl)
	fileUploadClient := fileuploadmock.NewMockClient(ctrl)

	// Unauthorized either won't have an orgId
	ictx.GetConfiguration().Set(configuration.ORGANIZATION, "")
	_, err := aibomcreate.AiBomWorkflow(ictx, nil)
	assert.EqualError(t, err, "Authentication error")

	// Or, Unauthorized users that provide an explicit orgId will be handled by the api availability check
	ictx.GetConfiguration().Set(configuration.ORGANIZATION, "5ffb5f8b-8cd3-4cfc-bce6-d23d19d4fa11")
	aiBomClient.EXPECT().CheckAPIAvailability(gomock.Any(), gomock.Any()).Times(1).
		Return(errors.NewUnauthorizedError(""))
	_, err = aibomcreate.RunAiBomWorkflow(ictx, frameworkmock.MockOrgID, aiBomClient, fileUploadClient, false)
	assert.EqualError(t, err, "Authentication error")
}

func TestFilterRuleCompositionDoesNotDuplicateGitignoreRules(t *testing.T) {
	const (
		gitignoreFilename = ".gitignore"
		ignoredFilename   = "ignored.txt"
	)

	root := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(root, gitignoreFilename),
		[]byte(ignoredFilename+"\n"),
		0o600,
	))

	logger := zerolog.Nop()
	pipelineRules, err := frameworkUtils.NewFileFilter(root, &logger).GetRules([]string{gitignoreFilename})
	require.NoError(t, err)

	legacyAdditionalRules, err := frameworkUtils.NewFileFilter(root, &logger).
		GetRules([]string{gitignoreFilename, ".dcignore", ".snyk"})
	require.NoError(t, err)

	currentAdditionalRules, err := frameworkUtils.NewFileFilter(root, &logger).
		GetRules([]string{".dcignore", ".snyk"})
	require.NoError(t, err)

	legacyRuleCounts := make(map[string]int, len(legacyAdditionalRules)+len(pipelineRules))
	for _, rule := range append(legacyAdditionalRules, pipelineRules...) {
		legacyRuleCounts[rule]++
	}

	currentRuleCounts := make(map[string]int, len(currentAdditionalRules)+len(pipelineRules))
	for _, rule := range append(currentAdditionalRules, pipelineRules...) {
		currentRuleCounts[rule]++
	}

	var gitignoreRuleCount int
	for _, rule := range pipelineRules {
		if !strings.Contains(rule, ignoredFilename) {
			continue
		}

		gitignoreRuleCount++
		assert.Equal(t, 2, legacyRuleCounts[rule])
		assert.Equal(t, 1, currentRuleCounts[rule])
	}
	require.Positive(t, gitignoreRuleCount)
}

func TestAiBomWorkflow_RespectsTrackedFilesFeatureFlag(t *testing.T) {
	const (
		gitignoreFilename        = ".gitignore"
		includedFilename         = "included.txt"
		trackedIgnoredFilename   = "tracked.ignored"
		untrackedIgnoredFilename = "untracked.ignored"
		dcIgnoredFilename        = "dcignored.txt"
		snykIgnoredFilename      = "snykignored.txt"
	)

	root := filepath.Join(t.TempDir(), "repo (team)")
	require.NoError(t, os.MkdirAll(root, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(root, trackedIgnoredFilename), []byte("tracked"), 0o600))

	repository, err := git.PlainInit(root, false)
	require.NoError(t, err)
	worktree, err := repository.Worktree()
	require.NoError(t, err)
	_, err = worktree.Add(trackedIgnoredFilename)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(
		filepath.Join(root, gitignoreFilename),
		[]byte("*.ignored\n"),
		0o600,
	))
	require.NoError(t, os.WriteFile(filepath.Join(root, untrackedIgnoredFilename), []byte("untracked"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, includedFilename), []byte("included"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, ".dcignore"), []byte(dcIgnoredFilename+"\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, dcIgnoredFilename), []byte("dc ignored"), 0o600))
	require.NoError(t, os.WriteFile(
		filepath.Join(root, ".snyk"),
		[]byte("exclude:\n  code:\n    - "+snykIgnoredFilename+"\n"),
		0o600,
	))
	require.NoError(t, os.WriteFile(filepath.Join(root, snykIgnoredFilename), []byte("snyk ignored"), 0o600))

	tests := []struct {
		name                string
		respectTrackedFiles bool
		wantTrackedFile     bool
	}{
		{
			name:                "preserves tracked files ignored only by gitignore when enabled",
			respectTrackedFiles: true,
			wantTrackedFile:     true,
		},
		{
			name:                "keeps legacy gitignore behavior when disabled",
			respectTrackedFiles: false,
			wantTrackedFile:     false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ictx := frameworkmock.NewMockInvocationContext(t)
			config := ictx.GetConfiguration()
			config.Set(configuration.INPUT_DIRECTORY, root)
			config.Set(frameworkUtils.FF_FILE_FILTER_METACHARACTER_FIX, true)
			config.Set(frameworkUtils.FF_GITIGNORE_RESPECT_TRACKED_FILES, test.respectTrackedFiles)

			ctrl := gomock.NewController(t)
			aiBomClient := aibomclientmock.NewMockAiBomClient(ctrl)
			fileUploadClient := fileuploadmock.NewMockClient(ctrl)
			uploadRevisionID := uuid.New()

			var uploadedPaths []string
			fileUploadClient.EXPECT().
				CreateRevisionFromChan(gomock.Any(), gomock.Any(), root).
				DoAndReturn(func(_ context.Context, paths <-chan string, _ string) (fileupload.UploadResult, error) {
					for path := range paths {
						uploadedPaths = append(uploadedPaths, path)
					}
					return fileupload.UploadResult{RevisionID: uploadRevisionID}, nil
				})

			aiBomClient.EXPECT().CheckAPIAvailability(gomock.Any(), frameworkmock.MockOrgID).Return(nil)
			aiBomClient.EXPECT().
				GenerateAIBOM(gomock.Any(), frameworkmock.MockOrgID, uploadRevisionID, false).
				Return(exampleAIBOM, testAIBOMID, nil)

			_, runErr := aibomcreate.RunAiBomWorkflow(
				ictx,
				frameworkmock.MockOrgID,
				aiBomClient,
				fileUploadClient,
				false,
			)
			require.NoError(t, runErr)

			trackedIgnoredPath := filepath.Join(root, trackedIgnoredFilename)
			if test.wantTrackedFile {
				assert.Contains(t, uploadedPaths, trackedIgnoredPath)
			} else {
				assert.NotContains(t, uploadedPaths, trackedIgnoredPath)
			}
			assert.NotContains(t, uploadedPaths, filepath.Join(root, untrackedIgnoredFilename))
			assert.NotContains(t, uploadedPaths, filepath.Join(root, dcIgnoredFilename))
			assert.NotContains(t, uploadedPaths, filepath.Join(root, snykIgnoredFilename))
			assert.Contains(t, uploadedPaths, filepath.Join(root, includedFilename))
		})
	}
}
