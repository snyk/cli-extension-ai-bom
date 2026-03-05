package redteam

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-ai-bom/internal/commands/redteam"
	"github.com/snyk/cli-extension-ai-bom/internal/utils"
)

func Init(e workflow.Engine) error {
	// NOTE(pkey): opts into the framework's RetryMiddleware which retries transient
	// HTTP errors (429, 500, 502, 503, 504) with exponential backoff. The framework defaults
	// to 1 attempt (no retries) unless PREVIEW_FEATURES_ENABLED is set. Ideally this default
	// should be changed in go-application-framework so all extensions benefit automatically.
	utils.EnableNetworkRetries(e.GetConfiguration())
	if err := redteam.RegisterWorkflows(e); err != nil {
		return fmt.Errorf("error registering redteam workflow: %w", err)
	}
	return nil
}
