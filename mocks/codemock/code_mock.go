// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/snyk/cli-extension-ai-bom/internal/services/code (interfaces: CodeService)
//
// Generated by this command:
//
//	mockgen -package codemock -destination codemock/code_mock.go github.com/snyk/cli-extension-ai-bom/internal/services/code CodeService
//

// Package codemock is a generated GoMock package.
package codemock

import (
	http "net/http"
	reflect "reflect"

	zerolog "github.com/rs/zerolog"
	errors "github.com/snyk/cli-extension-ai-bom/internal/errors"
	code "github.com/snyk/cli-extension-ai-bom/internal/services/code"
	scan "github.com/snyk/code-client-go/scan"
	configuration "github.com/snyk/go-application-framework/pkg/configuration"
	ui "github.com/snyk/go-application-framework/pkg/ui"
	gomock "go.uber.org/mock/gomock"
)

// MockCodeService is a mock of CodeService interface.
type MockCodeService struct {
	ctrl     *gomock.Controller
	recorder *MockCodeServiceMockRecorder
	isgomock struct{}
}

// MockCodeServiceMockRecorder is the mock recorder for MockCodeService.
type MockCodeServiceMockRecorder struct {
	mock *MockCodeService
}

// NewMockCodeService creates a new mock instance.
func NewMockCodeService(ctrl *gomock.Controller) *MockCodeService {
	mock := &MockCodeService{ctrl: ctrl}
	mock.recorder = &MockCodeServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockCodeService) EXPECT() *MockCodeServiceMockRecorder {
	return m.recorder
}

// Analyze mocks base method.
func (m *MockCodeService) Analyze(path string, depgraph map[string][]byte, httpClientFunc func() *http.Client, logger *zerolog.Logger, config configuration.Configuration, userInterface ui.UserInterface) (*code.AnalysisResponse, *scan.ResultMetaData, *errors.AiBomError) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Analyze", path, depgraph, httpClientFunc, logger, config, userInterface)
	ret0, _ := ret[0].(*code.AnalysisResponse)
	ret1, _ := ret[1].(*scan.ResultMetaData)
	ret2, _ := ret[2].(*errors.AiBomError)
	return ret0, ret1, ret2
}

// Analyze indicates an expected call of Analyze.
func (mr *MockCodeServiceMockRecorder) Analyze(path, depgraph, httpClientFunc, logger, config, userInterface any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Analyze", reflect.TypeOf((*MockCodeService)(nil).Analyze), path, depgraph, httpClientFunc, logger, config, userInterface)
}
