package main

import (
	"log"

	"github.com/snyk/go-application-framework/pkg/devtools"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-ai-bom/pkg/aibom"
	"github.com/snyk/cli-extension-ai-bom/pkg/redteam"
)

func initAll(e workflow.Engine) error {
	if err := aibom.Init(e); err != nil {
		return err
	}
	if err := redteam.Init(e); err != nil {
		return err
	}
	return nil
}

func main() {
	cmd, err := devtools.Cmd(initAll)
	if err != nil {
		log.Fatal(err)
	}
	cmd.SilenceUsage = true
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
