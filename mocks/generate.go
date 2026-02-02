package mocks

// External library mocks
//go:generate mockgen -package frameworkmock -destination frameworkmock/ui_mock.go "github.com/snyk/go-application-framework/pkg/ui" UserInterface,ProgressBar
//go:generate mockgen -package httpmock -destination httpmock/round_tripper_mock.go net/http RoundTripper

// Local library mocks
//go:generate mockgen -package aibomclientmock -destination aibomclientmock/client_mock.go github.com/snyk/cli-extension-ai-bom/internal/services/ai-bom-client AiBomClient
//go:generate mockgen -package redteamclientmock -destination redteamclientmock/client_mock.go github.com/snyk/cli-extension-ai-bom/internal/services/red-team-client RedTeamClient
