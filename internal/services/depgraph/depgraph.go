package depgraph

import (
	"encoding/json"
	goErrors "errors"
	"fmt"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

//revive:disable:exported // The interface must be called DepgraphService to standardize.
type DepgraphService interface {
	GetDepgraph(ictx workflow.InvocationContext) (*DepgraphResult, error)
}

// DepgraphServiceImpl is an implementation of our DepgraphService using open telemetry.
type DepgraphServiceImpl struct {
	depGraphWorkflowID workflow.Identifier
}

var _ DepgraphService = (*DepgraphServiceImpl)(nil) // Assert that DepgraphServiceImpl implements DepgraphService

type DepgraphResult struct {
	DepgraphBytes []json.RawMessage
}

func NewDepgraphServiceImpl() *DepgraphServiceImpl {
	return &DepgraphServiceImpl{
		depGraphWorkflowID: workflow.NewWorkflowIdentifier("depgraph"),
	}
}

func (dg *DepgraphServiceImpl) GetDepgraph(ictx workflow.InvocationContext) (*DepgraphResult, error) {
	engine := ictx.GetEngine()
	if engine == nil {
		return nil, goErrors.New("failed to get engine for depgraphs")
	}

	config := ictx.GetConfiguration()
	logger := ictx.GetEnhancedLogger()

	logger.Debug().Msgf("Invoking depgraph workflow\n")

	depGraphConfig := config.Clone()
	depGraphs, err := engine.InvokeWithConfig(dg.depGraphWorkflowID, depGraphConfig)
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

	return &DepgraphResult{
		DepgraphBytes: depGraphsBytes,
	}, nil
}

func getPayloadBytes(data workflow.Data) ([]byte, error) {
	payload := data.GetPayload()
	bytes, ok := payload.([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid payload type (want []byte, got %T)", payload)
	}
	return bytes, nil
}
