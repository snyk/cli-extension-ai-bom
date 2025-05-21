package mocks

// External library mocks
//go:generate mockgen -package frameworkmock -destination frameworkmock/ui_mock.go "github.com/snyk/go-application-framework/pkg/ui" UserInterface,ProgressBar
//go:generate mockgen -package httpmock -destination httpmock/round_tripper_mock.go net/http RoundTripper

// Local library mocks
//go:generate mockgen -package codemock -destination codemock/code_mock.go github.com/snyk/cli-extension-ai-bom/internal/services/code CodeService
//go:generate mockgen -package depgraphmock -destination depgraphmock/depgraph_mock.go github.com/snyk/cli-extension-ai-bom/internal/services/depgraph DepgraphService
