package mocks

// External library mocks
//go:generate mockgen -package frameworkmock -destination frameworkmock/ui_mock.go "github.com/snyk/go-application-framework/pkg/ui" UserInterface,ProgressBar

// Local library mocks
//go:generate mockgen -package codemock -destination codemock/code_mock.go github.com/snyk/cli-extension-ai-bom/internal/services/code CodeService
