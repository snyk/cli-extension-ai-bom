package aibomcreate_test

import (
	"bytes"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-ai-bom/internal/commands/aibomcreate"
	"github.com/snyk/cli-extension-ai-bom/mocks/frameworkmock"
)

func TestRenderPrettyResult_EmptyIssues(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(configuration.API_URL, "https://api.snyk.io")

	res := &aibomcreate.TestResult{
		Issues:  []aibomcreate.PolicyTestIssue{},
		Summary: []byte(`{"results":[]}`),
	}
	var buf bytes.Buffer
	err := aibomcreate.RenderPrettyResult(ictx, &buf, res)
	require.NoError(t, err)
	out := buf.String()

	assert.Contains(t, out, "AI BOM policy test")
	assert.Contains(t, out, "Open issues:")
	assert.Contains(t, out, "No issues found.")
	assert.Contains(t, out, "Ignored issues:")
	assert.Contains(t, out, "Test summary")
}

func TestRenderPrettyResult_OpenIssueWithPolicyAndRemediation(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(configuration.API_URL, "https://api.snyk.io")

	res := &aibomcreate.TestResult{
		Issues: []aibomcreate.PolicyTestIssue{
			{
				ID:                "issue-1",
				Description:       "Missing license file",
				Severity:          "high",
				PolicyID:          "pol-abc-123",
				State:             "open",
				RemediationAdvice: "Add a LICENSE file to the repo.",
			},
		},
		Summary: []byte(`{"results":[{"severity":"high","total":1,"open":1,"ignored":0}]}`),
	}
	var buf bytes.Buffer
	err := aibomcreate.RenderPrettyResult(ictx, &buf, res)
	require.NoError(t, err)
	out := buf.String()

	assert.Contains(t, out, "Open issues:")
	assert.Contains(t, out, "Missing license file")
	assert.Contains(t, out, "[HIGH]")
	assert.Contains(t, out, "https://evo.snyk.io/policies/pol-abc-123")
	assert.Contains(t, out, "Remediation: Add a LICENSE file to the repo.")
	assert.Contains(t, out, "Ignored issues:")
	assert.Contains(t, out, "Test summary")
}

func TestRenderPrettyResult_PolicyURLWithoutApiHost(t *testing.T) {
	// When API URL does not contain "api.", policy link is just the policy ID.
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(configuration.API_URL, "https://custom.snyk.io")

	res := &aibomcreate.TestResult{
		Issues: []aibomcreate.PolicyTestIssue{
			{
				ID:          "issue-1",
				Description: "Some issue",
				Severity:    "medium",
				PolicyID:    "pol-xyz",
				State:       "open",
			},
		},
		Summary: []byte(`{"results":[]}`),
	}
	var buf bytes.Buffer
	err := aibomcreate.RenderPrettyResult(ictx, &buf, res)
	require.NoError(t, err)
	out := buf.String()

	assert.Contains(t, out, "Policy: pol-xyz")
	assert.NotContains(t, out, "evo.snyk.io")
}

func TestRenderPrettyResult_OpenAndIgnoredIssues(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(configuration.API_URL, "https://api.snyk.io")

	res := &aibomcreate.TestResult{
		Issues: []aibomcreate.PolicyTestIssue{
			{ID: "1", Description: "Open one", Severity: "critical", State: "open"},
			{ID: "2", Description: "Ignored one", Severity: "low", State: "ignored"},
		},
		Summary: []byte(`{"results":[]}`),
	}
	var buf bytes.Buffer
	err := aibomcreate.RenderPrettyResult(ictx, &buf, res)
	require.NoError(t, err)
	out := buf.String()

	assert.Contains(t, out, "Open issues:")
	assert.Contains(t, out, "Open one")
	assert.Contains(t, out, "[CRITICAL]")
	assert.Contains(t, out, "Ignored issues:")
	assert.Contains(t, out, "Ignored one")
	assert.Contains(t, out, "[LOW]")
	// Summary section shows counts per state
	assert.Contains(t, out, "Open issues: 1")
	assert.Contains(t, out, "Ignored issues: 1")
}

func TestRenderPrettyResult_NoPolicyLineWhenPolicyIDEmpty(t *testing.T) {
	ictx := frameworkmock.NewMockInvocationContext(t)
	ictx.GetConfiguration().Set(configuration.API_URL, "https://api.snyk.io")

	res := &aibomcreate.TestResult{
		Issues: []aibomcreate.PolicyTestIssue{
			{ID: "1", Description: "No policy", Severity: "medium", State: "open", PolicyID: ""},
		},
		Summary: []byte(`{"results":[]}`),
	}
	var buf bytes.Buffer
	err := aibomcreate.RenderPrettyResult(ictx, &buf, res)
	require.NoError(t, err)
	out := buf.String()

	assert.Contains(t, out, "No policy")
	// Presenter only writes "  Policy: ..." when PolicyID is non-empty.
	assert.NotContains(t, out, "  Policy: ")
}
