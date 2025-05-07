package aibomcreate

import (
	"encoding/json"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

var DepGraphWorkflowID = workflow.NewWorkflowIdentifier("depgraph")

type DepGraphResult struct {
	DepGraphBytes []json.RawMessage
}

func GetDepGraph(ictx workflow.InvocationContext) (*DepGraphResult, error) {
	engine := ictx.GetEngine()
	config := ictx.GetConfiguration()
	logger := ictx.GetLogger()

	logger.Println("Invoking depgraph workflow")

	depGraphConfig := config.Clone()
	depGraphs, err := engine.InvokeWithConfig(DepGraphWorkflowID, depGraphConfig)
	if err != nil {
		return nil, fmt.Errorf("error invoking depgraphs workflow: %w", err)
	}

	numGraphs := len(depGraphs)
	logger.Printf("Generated documents for %d depgraph(s)\n", numGraphs)
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
