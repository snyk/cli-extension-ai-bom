package main

import (
	"fmt"
	"log"
	"os"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/devtools"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-ai-bom/pkg/aibom"
	"github.com/snyk/cli-extension-ai-bom/pkg/redteam"
)

func initAll(e workflow.Engine) error {
	if err := aibom.Init(e); err != nil {
		return fmt.Errorf("aibom init: %w", err)
	}
	if err := redteam.Init(e); err != nil {
		return fmt.Errorf("redteam init: %w", err)
	}
	return nil
}

func main() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	for _, arg := range os.Args[1:] {
		if arg == "--debug" || arg == "-d" {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
			break
		}
	}

	cmd, err := devtools.Cmd(initAll)
	if err != nil {
		log.Fatal(err)
	}
	cmd.SilenceUsage = true
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
