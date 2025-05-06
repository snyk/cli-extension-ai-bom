package code_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/snyk/cli-extension-ai-bom/internal/services/code"
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

	mockFiltersFailure(mockRT, fmt.Errorf("filters error"))

	resp, _, err := codeService.Analyze(getDir(), clientFactory, logger, ictx.GetConfiguration(), ictx.GetUserInterface())

	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestAnalyze_BundleFails(t *testing.T) {
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
	mockBundleFailure(mockRT, fmt.Errorf("bundle error"))

	resp, _, err := codeService.Analyze(getDir(), clientFactory, logger, ictx.GetConfiguration(), ictx.GetUserInterface())

	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestAnalyze_AnalysisFails(t *testing.T) {
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
	mockAnalysisFailure(mockRT, fmt.Errorf("analysis error"))

	resp, _, err := codeService.Analyze(getDir(), clientFactory, logger, ictx.GetConfiguration(), ictx.GetUserInterface())

	assert.Error(t, err)
	assert.Nil(t, resp)
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

func mockFiltersFailure(mockRT *httpmock.MockRoundTripper, err error) {
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

func mockBundleFailure(mockRT *httpmock.MockRoundTripper, err error) {
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

func mockAnalysisFailure(mockRT *httpmock.MockRoundTripper, err error) {
	mockRT.EXPECT().RoundTrip(httpmock.ForRequest(http.MethodPost, "/analysis")).Return(nil, err).Times(1)
}
