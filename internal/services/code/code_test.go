//nolint:goconst // Reason: repeated strings in this file are acceptable
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

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/cli-extension-ai-bom/internal/services/code"
	"github.com/snyk/cli-extension-ai-bom/internal/utils"
	"github.com/snyk/cli-extension-ai-bom/mocks/frameworkmock"
	"github.com/snyk/cli-extension-ai-bom/mocks/httpmock"
	"github.com/snyk/cli-extension-ai-bom/mocks/loggermock"
)

func TestAnalyze_Happy(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRT := httpmock.NewMockRoundTripper(ctrl)

	clientFactory := func() *http.Client {
		return &http.Client{
			Transport: mockRT,
		}
	}
	logger := loggermock.NewNoOpLogger()
	ictx := frameworkmock.NewMockInvocationContext(t)

	codeService := code.NewCodeServiceImpl()

	depGraphMap := map[string][]byte{"/0.snykdepgraph": []byte("foo")}

	mockFiltersSuccess(mockRT)
	mockBundleSuccess(mockRT)
	mockBundleDepgraphsSuccess(mockRT)
	mockAnalysisInProgress(mockRT, code.AnalysisStatusProgress)
	mockAnalysisInProgress(mockRT, code.AnalysisStatusFetching)
	mockAnalysisInProgress(mockRT, code.AnalysisStatusParsing)
	mockAnalysisInProgress(mockRT, code.AnalysisStatusWaiting)
	mockAnalysisInProgress(mockRT, code.AnalysisStatusAnalyzing)
	mockAnalysisSuccess(mockRT)

	resp, _, err := codeService.Analyze(getDir(), depGraphMap, clientFactory, logger, ictx.GetConfiguration(), ictx.GetUserInterface())

	assert.Nil(t, err)
	assert.Equal(t, "my-aibom", resp.Sarif.Runs[0].Results[0].Message.Text)
}

func TestAnalyze_FiltersFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRT := httpmock.NewMockRoundTripper(ctrl)
	clientFactory := func() *http.Client {
		return &http.Client{
			Transport: mockRT,
		}
	}

	logger := loggermock.NewNoOpLogger()
	ictx := frameworkmock.NewMockInvocationContext(t)

	codeService := code.NewCodeServiceImpl()

	mockFiltersHTTPError(mockRT, fmt.Errorf("filters error"))

	resp, _, err := codeService.Analyze(getDir(), make(map[string][]byte), clientFactory, logger, ictx.GetConfiguration(), ictx.GetUserInterface())

	assert.Equal(t, "SNYK-AI-BOM-0001", err.SnykError.ErrorCode)
	assertSnykError(t, "Failed to upload bundle: error creating bundle...: Get \"/filters\": filters error.", err.SnykError)
	assert.Nil(t, resp)
}

func TestAnalyze_BundleHTTPError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRT := httpmock.NewMockRoundTripper(ctrl)

	clientFactory := func() *http.Client {
		return &http.Client{
			Transport: mockRT,
		}
	}

	logger := loggermock.NewNoOpLogger()
	ictx := frameworkmock.NewMockInvocationContext(t)

	codeService := code.NewCodeServiceImpl()

	mockFiltersSuccess(mockRT)
	mockBundleHTTPError(mockRT, fmt.Errorf("bundle error"))

	resp, _, err := codeService.Analyze(getDir(), make(map[string][]byte), clientFactory, logger, ictx.GetConfiguration(), ictx.GetUserInterface())

	assert.Equal(t, "SNYK-AI-BOM-0001", err.SnykError.ErrorCode)
	assertSnykError(t, "Failed to upload bundle: error creating bundle...: Post \"/bundle\": bundle error.", err.SnykError)
	assert.Nil(t, resp)
}

func TestAnalyze_DepgraphUploadError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRT := httpmock.NewMockRoundTripper(ctrl)

	clientFactory := func() *http.Client {
		return &http.Client{
			Transport: mockRT,
		}
	}
	logger := loggermock.NewNoOpLogger()
	ictx := frameworkmock.NewMockInvocationContext(t)

	codeService := code.NewCodeServiceImpl()

	depGraphMap := map[string][]byte{"/0.snykdepgraph": []byte("foo")}

	mockFiltersSuccess(mockRT)
	mockBundleSuccess(mockRT)
	mockBundleDepgraphsFailure(mockRT)

	resp, _, err := codeService.Analyze(getDir(), depGraphMap, clientFactory, logger, ictx.GetConfiguration(), ictx.GetUserInterface())

	assert.Nil(t, resp)
	assert.Equal(t, "SNYK-AI-BOM-0001", err.SnykError.ErrorCode)
	assertSnykError(t, "Failed to update bundle with depgraphs: Put \"/bundle/my-bundle-hash\": depgraphs error", err.SnykError)
}

func TestAnalyze_AuthenticationError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRT := httpmock.NewMockRoundTripper(ctrl)

	clientFactory := func() *http.Client {
		return &http.Client{
			Transport: mockRT,
		}
	}

	logger := loggermock.NewNoOpLogger()
	ictx := frameworkmock.NewMockInvocationContext(t)

	codeService := code.NewCodeServiceImpl()

	mockFiltersSuccess(mockRT)
	mockBundleHTTPError(mockRT, fmt.Errorf("Authentication error"))

	resp, _, err := codeService.Analyze(getDir(), make(map[string][]byte), clientFactory, logger, ictx.GetConfiguration(), ictx.GetUserInterface())

	assert.Equal(t, "SNYK-0005", err.SnykError.ErrorCode)
	assertSnykError(t, "Upload failed with authentication error.", err.SnykError)
	assert.Nil(t, resp)
}

func TestAnalyze_EmptyDirectory(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRT := httpmock.NewMockRoundTripper(ctrl)

	clientFactory := func() *http.Client {
		return &http.Client{
			Transport: mockRT,
		}
	}

	logger := loggermock.NewNoOpLogger()
	ictx := frameworkmock.NewMockInvocationContext(t)

	codeService := code.NewCodeServiceImpl()

	mockFiltersSuccess(mockRT)
	mockBundleHTTPError(mockRT, fmt.Errorf("no files to scan"))

	resp, _, err := codeService.Analyze(getDir(), make(map[string][]byte), clientFactory, logger, ictx.GetConfiguration(), ictx.GetUserInterface())

	assert.Equal(t, "SNYK-AI-BOM-0003", err.SnykError.ErrorCode)
	assert.Nil(t, resp)
}

func TestAnalyze_NoSupportedFiles(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRT := httpmock.NewMockRoundTripper(ctrl)

	clientFactory := func() *http.Client {
		return &http.Client{
			Transport: mockRT,
		}
	}

	logger := loggermock.NewNoOpLogger()
	ictx := frameworkmock.NewMockInvocationContext(t)

	codeService := code.NewCodeServiceImpl()

	mockFiltersSuccess(mockRT)
	mockEmptyBundle(mockRT)

	resp, _, err := codeService.Analyze(getDir(), make(map[string][]byte), clientFactory, logger, ictx.GetConfiguration(), ictx.GetUserInterface())

	assert.Equal(t, "SNYK-AI-BOM-0003", err.SnykError.ErrorCode)
	assert.Nil(t, resp)
}

func TestAnalyze_AnalysisAuthZError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRT := httpmock.NewMockRoundTripper(ctrl)

	clientFactory := func() *http.Client {
		return &http.Client{
			Transport: mockRT,
		}
	}

	logger := loggermock.NewNoOpLogger()
	ictx := frameworkmock.NewMockInvocationContext(t)

	codeService := code.NewCodeServiceImpl()

	mockFiltersSuccess(mockRT)
	mockBundleSuccess(mockRT)
	mockAnalysisAuthZError(mockRT)

	resp, _, err := codeService.Analyze(getDir(), make(map[string][]byte), clientFactory, logger, ictx.GetConfiguration(), ictx.GetUserInterface())

	assert.Equal(t, "SNYK-AI-BOM-0002", err.SnykError.ErrorCode)
	assertSnykError(t, "Analysis request failed with status code 403.", err.SnykError)
	assert.Nil(t, resp)
}

func TestAnalyze_AnalysisHTTPError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRT := httpmock.NewMockRoundTripper(ctrl)

	clientFactory := func() *http.Client {
		return &http.Client{
			Transport: mockRT,
		}
	}

	logger := loggermock.NewNoOpLogger()
	ictx := frameworkmock.NewMockInvocationContext(t)

	codeService := code.NewCodeServiceImpl()

	mockFiltersSuccess(mockRT)
	mockBundleSuccess(mockRT)
	mockAnalysisHTTPError(mockRT, fmt.Errorf("analysis error"))

	resp, _, err := codeService.Analyze(getDir(), make(map[string][]byte), clientFactory, logger, ictx.GetConfiguration(), ictx.GetUserInterface())

	assert.Equal(t, "SNYK-AI-BOM-0001", err.SnykError.ErrorCode)
	assertSnykError(t, "Analysis request HTTP error.", err.SnykError)
	assert.Nil(t, resp)
}

func TestAnalyze_AnalysisFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRT := httpmock.NewMockRoundTripper(ctrl)

	clientFactory := func() *http.Client {
		return &http.Client{
			Transport: mockRT,
		}
	}

	logger := loggermock.NewNoOpLogger()
	ictx := frameworkmock.NewMockInvocationContext(t)

	codeService := code.NewCodeServiceImpl()

	mockFiltersSuccess(mockRT)
	mockBundleSuccess(mockRT)
	mockAnalysisFailure(mockRT)

	resp, _, err := codeService.Analyze(getDir(), make(map[string][]byte), clientFactory, logger, ictx.GetConfiguration(), ictx.GetUserInterface())

	assert.Equal(t, "SNYK-AI-BOM-0001", err.SnykError.ErrorCode)
	assertSnykError(t, "Analysis has ended with status: FAILED.", err.SnykError)
	assert.Nil(t, resp)
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

func mockAnalysisInProgress(mockRT *httpmock.MockRoundTripper, status string) {
	mockRT.EXPECT().RoundTrip(httpmock.ForRequest(http.MethodPost, "/analysis")).DoAndReturn(
		func(r *http.Request) (*http.Response, error) {
			if !checkRequestBundleHash(r, "my-new-bundle-hash") {
				return nil, fmt.Errorf("bundle hash does not match expected value")
			}
			bodyBytes, _ := json.Marshal(code.AnalysisResponse{Status: status})
			body := string(bodyBytes)

			resp := &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(body)),
				Header:     make(http.Header),
			}
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	).Times(1)
}

func mockAnalysisSuccess(mockRT *httpmock.MockRoundTripper) {
	mockRT.EXPECT().RoundTrip(httpmock.ForRequest(http.MethodPost, "/analysis")).DoAndReturn(
		func(r *http.Request) (*http.Response, error) {
			if !checkRequestBundleHash(r, "my-new-bundle-hash") {
				return nil, fmt.Errorf("bundle hash does not match expected value")
			}
			sarif := code.Sarif{Runs: []code.SarifRun{{Results: []code.SarifResult{{Message: code.SarifMessage{Text: "my-aibom"}}}}}}
			bodyBytes, _ := json.Marshal(code.AnalysisResponse{Status: "COMPLETE", Sarif: sarif})
			body := string(bodyBytes)

			resp := &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(body)),
				Header:     make(http.Header),
			}
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	).Times(1)
}

func mockAnalysisFailure(mockRT *httpmock.MockRoundTripper) {
	mockRT.EXPECT().RoundTrip(httpmock.ForRequest(http.MethodPost, "/analysis")).DoAndReturn(
		func(_ *http.Request) (*http.Response, error) {
			bodyBytes, _ := json.Marshal(code.AnalysisResponse{Status: "FAILED"})
			body := string(bodyBytes)
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(body)),
				Header:     make(http.Header),
			}
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	).Times(1)
}

func mockAnalysisHTTPError(mockRT *httpmock.MockRoundTripper, err error) {
	mockRT.EXPECT().RoundTrip(httpmock.ForRequest(http.MethodPost, "/analysis")).Return(nil, err).Times(1)
}

func mockAnalysisAuthZError(mockRT *httpmock.MockRoundTripper) {
	mockRT.EXPECT().RoundTrip(httpmock.ForRequest(http.MethodPost, "/analysis")).Return(&http.Response{StatusCode: http.StatusForbidden}, nil).Times(1)
}

func checkRequestBundleHash(r *http.Request, expectedHash string) bool {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return false
	}
	var data map[string]interface{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return false
	}
	keyMap, ok := data["key"].(map[string]interface{})
	if !ok {
		return false
	}
	hash, ok := keyMap["hash"].(string)
	if !ok {
		return false
	}
	return hash == expectedHash
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
	var snykErr snyk_errors.Error
	if errors.As(err, &snykErr) {
		assert.Equal(t, expectedMsg, snykErr.Detail)
	} else {
		t.Fatalf("expected error of type snyk_errors.Error, got: %T", err)
	}
}
