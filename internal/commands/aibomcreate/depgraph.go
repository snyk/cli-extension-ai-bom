package aibomcreate

import (
	"encoding/json"
	goErrors "errors"
	"fmt"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

var DepGraphWorkflowID = workflow.NewWorkflowIdentifier("depgraph")

type DepGraphResult struct {
	DepGraphBytes []json.RawMessage
}

func GetDepGraph(ictx workflow.InvocationContext) (*DepGraphResult, error) {
	engine := ictx.GetEngine()
	if engine == nil {
		return nil, goErrors.New("failed to get engine for depgraphs")
	}

	config := ictx.GetConfiguration()
	logger := ictx.GetEnhancedLogger()

	logger.Debug().Msgf("Invoking depgraph workflow\n")

	depGraphConfig := config.Clone()
	depGraphs, err := engine.InvokeWithConfig(DepGraphWorkflowID, depGraphConfig)
	if err != nil {
		return nil, fmt.Errorf("error generating depgraphs: %w", err)
	}

	numGraphs := len(depGraphs)
	logger.Debug().Msgf("Generated documents for %d depgraph(s)\n", numGraphs)
	depGraphsBytes := make([]json.RawMessage, numGraphs)
	for i, depGraph := range depGraphs {
		depGraphBytes, err := getPayloadBytes(depGraph)
		if err != nil {
			return nil, err
		}
		depGraphsBytes[i] = depGraphBytes
	}

	return &DepGraphResult{
		DepGraphBytes: depGraphsBytes,
	}, nil
}
