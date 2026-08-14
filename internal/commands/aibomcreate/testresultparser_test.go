package aibomcreate_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-ai-bom/internal/commands/aibomcreate"
)

func TestParseTestResult_SingleOpenIssue(t *testing.T) {
	jsonStr := `{
		"data":{
			"id":"run-1",
			"type":"test",
			"attributes":{
				"issues":[{
					"id":"issue-1",
					"description":"Missing license",
					"severity":"high",
					"policy_id":"pol-123",
					"state":"open",
					"source":"policy",
					"remediation_advice":"Add a LICENSE file"
				}]
			}
		}
	}`
	res, err := aibomcreate.ParseTestResult(jsonStr)
	require.NoError(t, err)
	require.Len(t, res.Issues, 1)
	assert.Equal(t, "issue-1", res.Issues[0].ID)
	assert.Equal(t, "Missing license", res.Issues[0].Description)
	assert.Equal(t, "high", res.Issues[0].Severity)
	assert.Equal(t, "pol-123", res.Issues[0].PolicyID)
	assert.Equal(t, aibomcreate.IssueStateOpen, res.Issues[0].State)
	assert.Equal(t, "Add a LICENSE file", res.Issues[0].RemediationAdvice)

	var summary struct {
		Results []struct {
			Severity string `json:"severity"`
			Total    int    `json:"total"`
			Open     int    `json:"open"`
			Ignored  int    `json:"ignored"`
		} `json:"results"`
	}
	err = json.Unmarshal(res.Summary, &summary)
	require.NoError(t, err)
	require.Len(t, summary.Results, 1)
	assert.Equal(t, "high", summary.Results[0].Severity)
	assert.Equal(t, 1, summary.Results[0].Total)
	assert.Equal(t, 1, summary.Results[0].Open)
	assert.Equal(t, 0, summary.Results[0].Ignored)
}

func TestParseTestResult_SortsBySeverity(t *testing.T) {
	jsonStr := `{
		"data":{
			"id":"run-1",
			"type":"test",
			"attributes":{
				"issues":[
					{"id":"a","description":"Low","severity":"low","state":"open"},
					{"id":"b","description":"Critical","severity":"critical","state":"open"},
					{"id":"c","description":"Medium","severity":"medium","state":"open"},
					{"id":"d","description":"High","severity":"high","state":"open"}
				]
			}
		}
	}`
	res, err := aibomcreate.ParseTestResult(jsonStr)
	require.NoError(t, err)
	require.Len(t, res.Issues, 4)
	assert.Equal(t, "critical", res.Issues[0].Severity)
	assert.Equal(t, "high", res.Issues[1].Severity)
	assert.Equal(t, "medium", res.Issues[2].Severity)
	assert.Equal(t, "low", res.Issues[3].Severity)
}

func TestParseTestResult_FiltersOutClosedIssues(t *testing.T) {
	jsonStr := `{
		"data":{
			"id":"run-1",
			"type":"test",
			"attributes":{
				"issues":[
					{"id":"open-1","description":"Open","severity":"high","state":"open"},
					{"id":"ignored-1","description":"Ignored","severity":"medium","state":"ignored"},
					{"id":"closed-1","description":"Closed","severity":"low","state":"closed"}
				]
			}
		}
	}`
	res, err := aibomcreate.ParseTestResult(jsonStr)
	require.NoError(t, err)
	require.Len(t, res.Issues, 2)
	ids := make([]string, len(res.Issues))
	for i, iss := range res.Issues {
		ids[i] = iss.ID
	}
	assert.ElementsMatch(t, []string{"open-1", "ignored-1"}, ids)
}

func TestParseTestResult_SummaryCountsOpenAndIgnored(t *testing.T) {
	jsonStr := `{
		"data":{
			"id":"run-1",
			"type":"test",
			"attributes":{
				"issues":[
					{"id":"1","description":"A","severity":"high","state":"open"},
					{"id":"2","description":"B","severity":"high","state":"ignored"},
					{"id":"3","description":"C","severity":"medium","state":"open"}
				]
			}
		}
	}`
	res, err := aibomcreate.ParseTestResult(jsonStr)
	require.NoError(t, err)

	var summary struct {
		Results []struct {
			Severity string `json:"severity"`
			Total    int    `json:"total"`
			Open     int    `json:"open"`
			Ignored  int    `json:"ignored"`
		} `json:"results"`
	}
	err = json.Unmarshal(res.Summary, &summary)
	require.NoError(t, err)
	bySev := make(map[string]struct{ Total, Open, Ignored int })
	for _, r := range summary.Results {
		bySev[r.Severity] = struct{ Total, Open, Ignored int }{r.Total, r.Open, r.Ignored}
	}
	assert.Equal(t, 2, bySev["high"].Total)
	assert.Equal(t, 1, bySev["high"].Open)
	assert.Equal(t, 1, bySev["high"].Ignored)
	assert.Equal(t, 1, bySev["medium"].Total)
	assert.Equal(t, 1, bySev["medium"].Open)
	assert.Equal(t, 0, bySev["medium"].Ignored)
}

func TestParseTestResult_MissingData(t *testing.T) {
	// Empty root object: attributes.issues is nil; after filter we get empty slice.
	res, err := aibomcreate.ParseTestResult(`{}`)
	require.NoError(t, err)
	assert.Empty(t, res.Issues)
	assert.NotNil(t, res.Summary)
}

func TestFilterTestResult_FiltersIssues(t *testing.T) {
	jsonStr := `{
		"data":{
			"id":"run-1",
			"type":"test",
			"attributes":{
				"issues":[
					{"id":"1","description":"High","severity":"high","state":"open"},
					{"id":"2","description":"Low","severity":"low","state":"closed"}
				]
			}
		}
	}`

	filteredJSON, err := aibomcreate.FilterTestResult(jsonStr, "high")
	require.NoError(t, err)

	var raw struct {
		Data struct {
			Attributes struct {
				Issues []struct {
					ID       string `json:"id"`
					Severity string `json:"severity"`
				} `json:"issues"`
			} `json:"attributes"`
		} `json:"data"`
	}
	err = json.Unmarshal([]byte(filteredJSON), &raw)
	require.NoError(t, err)
	require.Len(t, raw.Data.Attributes.Issues, 1)
	assert.Equal(t, "1", raw.Data.Attributes.Issues[0].ID)
	assert.Equal(t, "high", raw.Data.Attributes.Issues[0].Severity)
}

func TestParseTestResult_AppliesSeverityThresholdFromFilteredJSON(t *testing.T) {
	jsonStr := `{
		"data":{
			"id":"run-1",
			"type":"test",
			"attributes":{
				"issues":[
					{"id":"1","description":"Critical","severity":"critical","state":"open"},
					{"id":"2","description":"High","severity":"high","state":"open"},
					{"id":"3","description":"Medium","severity":"medium","state":"open"},
					{"id":"4","description":"Low","severity":"low","state":"ignored"}
				]
			}
		}
	}`

	filteredJSON, err := aibomcreate.FilterTestResult(jsonStr, "high")
	require.NoError(t, err)

	parsed, err := aibomcreate.ParseTestResult(filteredJSON)
	require.NoError(t, err)
	require.Len(t, parsed.Issues, 2)
	assert.Equal(t, "critical", parsed.Issues[0].Severity)
	assert.Equal(t, "high", parsed.Issues[1].Severity)

	var summary struct {
		Results []struct {
			Severity string `json:"severity"`
			Total    int    `json:"total"`
		} `json:"results"`
	}
	err = json.Unmarshal(parsed.Summary, &summary)
	require.NoError(t, err)
	require.Len(t, summary.Results, 2)
}
