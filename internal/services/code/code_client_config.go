package code

import (
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

type codeClientConfig struct {
	localConfiguration configuration.Configuration
}

func (c *codeClientConfig) Organization() string {
	return c.localConfiguration.GetString(configuration.ORGANIZATION)
}

func (c *codeClientConfig) IsFedramp() bool {
	return c.localConfiguration.GetBool(configuration.IS_FEDRAMP)
}

//nolint:revive,stylecheck // required name by code client
func (c *codeClientConfig) SnykCodeApi() string {
	return FilesBundleAPI(c.localConfiguration)
}

//nolint:revive,stylecheck // required name by code client
func (c *codeClientConfig) SnykApi() string {
	return c.localConfiguration.GetString(configuration.API_URL)
}

var defaultSnykCodeTimeout = time.Hour

func (c *codeClientConfig) SnykCodeAnalysisTimeout() time.Duration {
	if !c.localConfiguration.IsSet(configuration.TIMEOUT) {
		return defaultSnykCodeTimeout
	}
	timeoutInSeconds := c.localConfiguration.GetInt(configuration.TIMEOUT)
	return time.Duration(timeoutInSeconds) * time.Second
}
