//nolint:goconst // Reason: repeated strings in this file are acceptable
package code_test

import (
	"bytes"
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

	mockFiltersSuccess(mockRT)
	mockBundleSuccess(mockRT)
	mockAnalysisSuccess(mockRT)

	resp, _, err := codeService.Analyze(getDir(), clientFactory, logger, ictx.GetConfiguration(), ictx.GetUserInterface())

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

	resp, _, err := codeService.Analyze(getDir(), clientFactory, logger, ictx.GetConfiguration(), ictx.GetUserInterface())

	assert.Equal(t, "SNYK-AI-BOM-0001", err.SnykError.ErrorCode)
	assertSnykError(t, "failed to upload bundle: error creating bundle...: Get \"/filters\": filters error", err.SnykError)
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

	resp, _, err := codeService.Analyze(getDir(), clientFactory, logger, ictx.GetConfiguration(), ictx.GetUserInterface())

	assert.Equal(t, "SNYK-AI-BOM-0001", err.SnykError.ErrorCode)
	assertSnykError(t, "failed to upload bundle: error creating bundle...: Post \"/bundle\": bundle error", err.SnykError)
	assert.Nil(t, resp)
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

	resp, _, err := codeService.Analyze(getDir(), clientFactory, logger, ictx.GetConfiguration(), ictx.GetUserInterface())

	assert.Equal(t, "SNYK-0005", err.SnykError.ErrorCode)
	assertSnykError(t, "upload failed with authentication error", err.SnykError)
	assert.Nil(t, resp)
}

func TestAnalyze_EmptyBundleError(t *testing.T) {
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

	resp, _, err := codeService.Analyze(getDir(), clientFactory, logger, ictx.GetConfiguration(), ictx.GetUserInterface())

	assert.Equal(t, "SNYK-AI-BOM-0003", err.SnykError.ErrorCode)
	assertSnykError(t, "empty bundle hash", err.SnykError)
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

	resp, _, err := codeService.Analyze(getDir(), clientFactory, logger, ictx.GetConfiguration(), ictx.GetUserInterface())

	assert.Equal(t, "SNYK-AI-BOM-0002", err.SnykError.ErrorCode)
	assertSnykError(t, "analysis request failed with status code 403", err.SnykError)
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

	resp, _, err := codeService.Analyze(getDir(), clientFactory, logger, ictx.GetConfiguration(), ictx.GetUserInterface())

	assert.Equal(t, "SNYK-AI-BOM-0001", err.SnykError.ErrorCode)
	assertSnykError(t, "analysis request HTTP error", err.SnykError)
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

	resp, _, err := codeService.Analyze(getDir(), clientFactory, logger, ictx.GetConfiguration(), ictx.GetUserInterface())

	assert.Equal(t, "SNYK-AI-BOM-0001", err.SnykError.ErrorCode)
	assertSnykError(t, "analysis has completed with status: FAILED", err.SnykError)
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

func mockAnalysisSuccess(mockRT *httpmock.MockRoundTripper) {
	mockRT.EXPECT().RoundTrip(httpmock.ForRequest(http.MethodPost, "/analysis")).DoAndReturn(
		func(_ *http.Request) (*http.Response, error) {
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

func assertSnykError(t *testing.T, expectedMsg string, err error) {
	t.Helper()
	var snykErr snyk_errors.Error
	if errors.As(err, &snykErr) {
		assert.Equal(t, expectedMsg, snykErr.Detail)
	} else {
		t.Fatalf("expected error of type snyk_errors.Error, got: %T", err)
	}
}
