package code_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-ai-bom/internal/services/code"
	"github.com/snyk/cli-extension-ai-bom/mocks/frameworkmock"
	"github.com/snyk/cli-extension-ai-bom/mocks/loggermock"

	"go.uber.org/mock/gomock"
)

func TestAnalyze(t *testing.T) {
	gomock.NewController(t)
	client := &http.Client{}
	clientFactory := func() *http.Client { return client }

	server := NewTestServer(t)

	logger := loggermock.NewNoOpLogger()
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(configuration.API_URL, server.URL)

	codeService := code.NewCodeServiceImpl()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("unable to get current file path")
	}
	dir := filepath.Dir(filename)

	resp, _, err := codeService.Analyze(dir, clientFactory, logger, ictx.GetConfiguration(), ictx.GetUserInterface())

	assert.Nil(t, err)
	assert.Equal(t, "my-aibom", resp.Sarif.Runs[0].Results[0].Message.Text)
}

type TestServer struct {
	*httptest.Server
	Requests []*http.Request
	mu       sync.Mutex
}

func NewTestServer(t *testing.T) *TestServer {
	t.Helper()

	ts := &TestServer{}

	ts.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.mu.Lock()
		ts.Requests = append(ts.Requests, r.Clone(r.Context()))
		ts.mu.Unlock()
		switch r.URL.Path {
		case "/filters":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
    "configFiles": [],
    "extensions": [".go"],
    "autofixExtensions": []
}`))
		case "/bundle":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"bundleHash": "my-bundle-hash", "missingFiles": []}`))
		case "/analysis":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			sarif := code.Sarif{Runs: []code.SarifRun{{Results: []code.SarifResult{{Message: code.SarifMessage{Text: "my-aibom"}}}}}}
			body, _ := json.Marshal(code.AnalysisResponse{Status: "COMPLETE", Sarif: sarif})
			w.Write(body)
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("path not handled"))
		}
	}))

	t.Cleanup(ts.Close)
	return ts
}
