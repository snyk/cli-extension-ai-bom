package htmlreport

import (
	_ "embed"
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-ai-bom/internal/utils"
)

//go:embed redteam-report.html
var redteamHTMLTemplate string

var redteamWorkflowID = workflow.NewWorkflowIdentifier("redteam")

func ProcessResults(
	logger *zerolog.Logger,
	config configuration.Configuration,
	jsonResults []workflow.Data,
) ([]workflow.Data, error) {
	returnHTML := config.GetBool(utils.FlagHTML)
	htmlFileOutput := config.GetString(utils.FlagHTMLFileOutput)
	needsHTML := returnHTML || htmlFileOutput != ""

	var htmlOutput string
	if needsHTML {
		var err error
		htmlOutput, err = fromResults(jsonResults)
		if err != nil {
			return nil, fmt.Errorf("failed generating HTML report: %w", err)
		}
	}

	if htmlFileOutput != "" {
		if err := os.WriteFile(htmlFileOutput, []byte(htmlOutput), 0o600); err != nil {
			return nil, fmt.Errorf("failed writing HTML report to %s: %w", htmlFileOutput, err)
		}
		logger.Info().Msgf("HTML report written to %s", htmlFileOutput)
	}

	if returnHTML {
		htmlData := workflow.NewData(
			workflow.NewTypeIdentifier(redteamWorkflowID, "redteam"),
			"text/html",
			[]byte(htmlOutput),
		)
		return []workflow.Data{htmlData}, nil
	}

	return jsonResults, nil
}

func fromResults(results []workflow.Data) (string, error) {
	if len(results) == 0 {
		return "", fmt.Errorf("no results to generate HTML from")
	}

	payload, ok := results[0].GetPayload().([]byte)
	if !ok {
		return "", fmt.Errorf("unexpected payload type")
	}

	return generateRedTeamHTML(string(payload))
}

func generateRedTeamHTML(jsonData string) (string, error) {
	tmpl, err := template.New("redteam-report").Parse(redteamHTMLTemplate)
	if err != nil {
		return "", fmt.Errorf("error parsing HTML template: %w", err)
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, jsonData); err != nil {
		return "", fmt.Errorf("error executing HTML template: %w", err)
	}

	return buf.String(), nil
}
