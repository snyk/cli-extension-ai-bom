package utils

import (
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking/middleware"
)

const (
	// shared flags.
	FlagExperimental = "experimental"
	FlagHTML         = "html"

	// aibom flags.

	ConfigurationSnykCodeClientProxyURL = "SNYK_CODE_CLIENT_PROXY_URL"
	FlagUpload                          = "upload"
	FlagRepoName                        = "repo"

	// redteam flags.
	FlagConfig                 = "config"
	FlagHTMLFileOutput         = "html-file-output"
	FlagRedTeamScanningAgentID = "scanning-agent-id"

	// redteam scanning-agent flags.
	FlagScanningAgentName = "name"
	FlagScanningAgentID   = "id"

	networkRetryAttempts = 3
)

func EnableNetworkRetries(config configuration.Configuration) {
	config.Set(middleware.ConfigurationKeyRetryAttempts, networkRetryAttempts)
}
