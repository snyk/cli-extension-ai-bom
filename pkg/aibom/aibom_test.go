package aibom_test

import (
	"net/url"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-ai-bom/internal/commands/aibomcreate"
	"github.com/snyk/cli-extension-ai-bom/pkg/aibom"
)

func TestInit(t *testing.T) {
	c := configuration.New()
	e := workflow.NewWorkFlowEngine(c)

	err := e.Init()
	assert.NoError(t, err)

	err = aibom.Init(e)
	assert.NoError(t, err)

	assertWorkflowExists(t, e, aibomcreate.WorkflowID)
}

func assertWorkflowExists(t *testing.T, e workflow.Engine, id *url.URL) {
	t.Helper()

	wflw, ok := e.GetWorkflow(id)
	assert.False(t, ok) // TODO assert True when command is ready
	assert.Nil(t, wflw) // TODO assert NotNil when command is ready
}
