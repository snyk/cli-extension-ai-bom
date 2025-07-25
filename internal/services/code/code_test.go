package code_test

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	internal_errors "github.com/snyk/cli-extension-ai-bom/internal/errors"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/cli-extension-ai-bom/internal/services/code"
	"github.com/snyk/cli-extension-ai-bom/internal/utils"
	"github.com/snyk/cli-extension-ai-bom/mocks/frameworkmock"
	"github.com/snyk/cli-extension-ai-bom/mocks/httpmock"
	"github.com/snyk/cli-extension-ai-bom/mocks/loggermock"
)

func TestUploadBundle_Happy(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRT := httpmock.NewMockRoundTripper(ctrl)

	httpClient := &http.Client{
		Transport: mockRT,
	}
	logger := loggermock.NewNoOpLogger()
	ictx := frameworkmock.NewMockInvocationContext(t)

	codeService := code.NewCodeServiceImpl()

	depGraphMap := map[string][]byte{"/0.snykdepgraph": []byte("foo")}

	mockFiltersSuccess(mockRT)
	mockBundleSuccess(mockRT)
	mockBundleDepgraphsSuccess(mockRT)

	bundleHash, err := codeService.UploadBundle(getDir(), depGraphMap, httpClient, logger, ictx.GetConfiguration(), ictx.GetUserInterface())

	assert.Nil(t, err)
	assert.Equal(t, "my-new-bundle-hash", bundleHash)
}

func TestUploadBundle_FiltersFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRT := httpmock.NewMockRoundTripper(ctrl)
	httpClient := &http.Client{
		Transport: mockRT,
	}

	logger := loggermock.NewNoOpLogger()
	ictx := frameworkmock.NewMockInvocationContext(t)

	codeService := code.NewCodeServiceImpl()

	mockFiltersHTTPError(mockRT, fmt.Errorf("filters error"))

	bundleHash, err := codeService.UploadBundle(getDir(), make(map[string][]byte), httpClient, logger, ictx.GetConfiguration(), ictx.GetUserInterface())

	assert.Equal(t, internal_errors.NewInternalError("").SnykError.ErrorCode, err.SnykError.ErrorCode)
	assertSnykError(t, "Failed to upload bundle: error creating bundle...: Get \"/filters\": filters error.", err.SnykError)
	assert.Equal(t, "", bundleHash)
}

func TestUploadBundle_BundleHTTPError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRT := httpmock.NewMockRoundTripper(ctrl)

	httpClient := &http.Client{
		Transport: mockRT,
	}

	logger := loggermock.NewNoOpLogger()
	ictx := frameworkmock.NewMockInvocationContext(t)

	codeService := code.NewCodeServiceImpl()

	mockFiltersSuccess(mockRT)
	mockBundleHTTPError(mockRT, fmt.Errorf("bundle error"))

	bundleHash, err := codeService.UploadBundle(getDir(), make(map[string][]byte), httpClient, logger, ictx.GetConfiguration(), ictx.GetUserInterface())

	assert.Equal(t, internal_errors.NewInternalError("").SnykError.ErrorCode, err.SnykError.ErrorCode)
	assertSnykError(t, "Failed to upload bundle: error creating bundle...: Post \"/bundle\": bundle error.", err.SnykError)
	assert.Equal(t, "", bundleHash)
}

func TestUploadBundle_DepgraphUploadError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRT := httpmock.NewMockRoundTripper(ctrl)

	httpClient := &http.Client{
		Transport: mockRT,
	}
	logger := loggermock.NewNoOpLogger()
	ictx := frameworkmock.NewMockInvocationContext(t)

	codeService := code.NewCodeServiceImpl()

	depGraphMap := map[string][]byte{"/0.snykdepgraph": []byte("foo")}

	mockFiltersSuccess(mockRT)
	mockBundleSuccess(mockRT)
	mockBundleDepgraphsFailure(mockRT)

	bundleHash, err := codeService.UploadBundle(getDir(), depGraphMap, httpClient, logger, ictx.GetConfiguration(), ictx.GetUserInterface())

	assert.Equal(t, "", bundleHash)
	assert.Equal(t, internal_errors.NewInternalError("").SnykError.ErrorCode, err.SnykError.ErrorCode)
	assertSnykError(t, "Failed to update bundle with depgraphs: Put \"/bundle/my-bundle-hash\": depgraphs error", err.SnykError)
}

func TestUploadBundle_AuthenticationError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRT := httpmock.NewMockRoundTripper(ctrl)

	httpClient := &http.Client{
		Transport: mockRT,
	}

	logger := loggermock.NewNoOpLogger()
	ictx := frameworkmock.NewMockInvocationContext(t)

	codeService := code.NewCodeServiceImpl()

	mockFiltersSuccess(mockRT)
	mockBundleHTTPError(mockRT, fmt.Errorf("Authentication error"))

	bundleHash, err := codeService.UploadBundle(getDir(), make(map[string][]byte), httpClient, logger, ictx.GetConfiguration(), ictx.GetUserInterface())

	assert.Equal(t, internal_errors.NewUnauthorizedError("").SnykError.ErrorCode, err.SnykError.ErrorCode)
	assertSnykError(t, "Upload failed with authentication error.", err.SnykError)
	assert.Equal(t, "", bundleHash)
}

func TestUploadBundle_EmptyDirectory(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRT := httpmock.NewMockRoundTripper(ctrl)

	httpClient := &http.Client{
		Transport: mockRT,
	}

	logger := loggermock.NewNoOpLogger()
	ictx := frameworkmock.NewMockInvocationContext(t)

	codeService := code.NewCodeServiceImpl()

	mockFiltersSuccess(mockRT)
	mockBundleHTTPError(mockRT, fmt.Errorf("no files to scan"))

	bundleHash, err := codeService.UploadBundle(getDir(), make(map[string][]byte), httpClient, logger, ictx.GetConfiguration(), ictx.GetUserInterface())

	assert.Equal(t, internal_errors.NewNoSupportedFilesError().SnykError.ErrorCode, err.SnykError.ErrorCode)
	assert.Equal(t, "", bundleHash)
}

func TestUploadBundle_NoSupportedFiles(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRT := httpmock.NewMockRoundTripper(ctrl)

	httpClient := &http.Client{
		Transport: mockRT,
	}

	logger := loggermock.NewNoOpLogger()
	ictx := frameworkmock.NewMockInvocationContext(t)

	codeService := code.NewCodeServiceImpl()

	mockFiltersSuccess(mockRT)
	mockEmptyBundle(mockRT)

	bundleHash, err := codeService.UploadBundle(getDir(), make(map[string][]byte), httpClient, logger, ictx.GetConfiguration(), ictx.GetUserInterface())

	assert.Equal(t, internal_errors.NewNoSupportedFilesError().SnykError.ErrorCode, err.SnykError.ErrorCode)
	assert.Equal(t, "", bundleHash)
}

func TestSnykCodeAPIProxyUrl(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	config := ictx.GetConfiguration()
	config.Set(configuration.API_URL, "https://api.snyk.io")

	assert.Equal(t, code.SnykCodeAPI(config), "https://deeproxy.snyk.io")
	config.Set(utils.ConfigurationSnykCodeClientProxyURL, "http://localhost:1234")
	assert.Equal(t, code.SnykCodeAPI(config), "http://localhost:1234")
}

func getDir() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("unable to get current file path")
	}
	dir := filepath.Dir(filename)
	return dir
}

func mockFiltersSuccess(mockRT *httpmock.MockRoundTripper) {
	mockRT.EXPECT().RoundTrip(httpmock.ForRequest(http.MethodGet, "/filters")).DoAndReturn(
		func(_ *http.Request) (*http.Response, error) {
			body := `{
					"configFiles": [],
					"extensions": [".go"],
					"autofixExtensions": []
				}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(body)),
				Header:     make(http.Header),
			}, nil
		},
	).Times(1)
}

func mockFiltersHTTPError(mockRT *httpmock.MockRoundTripper, err error) {
	mockRT.EXPECT().RoundTrip(httpmock.ForRequest(http.MethodGet, "/filters")).Return(nil, err).Times(1)
}

func mockBundleSuccess(mockRT *httpmock.MockRoundTripper) {
	mockRT.EXPECT().RoundTrip(httpmock.ForRequest(http.MethodPost, "/bundle")).DoAndReturn(
		func(_ *http.Request) (*http.Response, error) {
			body := `{"bundleHash": "my-bundle-hash", "missingFiles": []}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(body)),
				Header:     make(http.Header),
			}, nil
		},
	).Times(1)
}

func mockBundleDepgraphsSuccess(mockRT *httpmock.MockRoundTripper) {
	mockRT.EXPECT().RoundTrip(httpmock.ForRequest(http.MethodPut, "/bundle/my-bundle-hash")).DoAndReturn(
		func(r *http.Request) (*http.Response, error) {
			if !checkRequestFileNameAndContent(r, "/0.snykdepgraph", "foo") {
				return nil, fmt.Errorf("depgraph file does not match")
			}
			body := `{"bundleHash": "my-new-bundle-hash", "missingFiles": []}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(body)),
				Header:     make(http.Header),
			}, nil
		},
	).Times(1)
}

func mockBundleDepgraphsFailure(mockRT *httpmock.MockRoundTripper) {
	mockRT.EXPECT().RoundTrip(httpmock.ForRequest(http.MethodPut, "/bundle/my-bundle-hash")).Return(nil, fmt.Errorf("depgraphs error")).Times(1)
}

func mockEmptyBundle(mockRT *httpmock.MockRoundTripper) {
	mockRT.EXPECT().RoundTrip(httpmock.ForRequest(http.MethodPost, "/bundle")).DoAndReturn(
		func(_ *http.Request) (*http.Response, error) {
			body := `{"bundleHash": "", "missingFiles": []}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(body)),
				Header:     make(http.Header),
			}, nil
		},
	).Times(1)
}

func mockBundleHTTPError(mockRT *httpmock.MockRoundTripper, err error) {
	mockRT.EXPECT().RoundTrip(httpmock.ForRequest(http.MethodPost, "/bundle")).Return(nil, err).Times(1)
}

func checkRequestFileNameAndContent(r *http.Request, expectedName, expectedContent string) bool {
	gr, err := gzip.NewReader(r.Body)
	if err != nil {
		return false
	}
	defer gr.Close()

	b64, err := io.ReadAll(gr)
	if err != nil {
		return false
	}
	content, err := base64.StdEncoding.DecodeString(string(b64))
	if err != nil {
		return false
	}
	var data map[string]interface{}
	err = json.Unmarshal(content, &data)
	if err != nil {
		return false
	}
	filesMap, ok := data["files"].(map[string]interface{})
	if !ok {
		return false
	}
	fileMap, ok := filesMap[expectedName].(map[string]interface{})
	if !ok {
		return false
	}
	fileContent, ok := fileMap["content"].(string)
	if !ok {
		return false
	}
	return fileContent == expectedContent
}

func assertSnykError(t *testing.T, expectedMsg string, err error) {
	t.Helper()
	var snykErr internal_errors.AiBomError
	if errors.As(err, &snykErr.SnykError) {
		assert.Equal(t, expectedMsg, snykErr.SnykError.Detail)
	} else {
		t.Fatalf("expected error of type snyk_errors.Error, got: %T", err)
	}
}
