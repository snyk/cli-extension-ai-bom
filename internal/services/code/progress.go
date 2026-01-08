package code

import (
	"github.com/rs/zerolog"
	"github.com/snyk/code-client-go/scan"

	"github.com/snyk/go-application-framework/pkg/ui"
)

type ProgressTrackerFactory struct {
	userInterface ui.UserInterface
	logger        *zerolog.Logger
}

func (p ProgressTrackerFactory) GenerateTracker() scan.Tracker {
	return &ProgressTrackerAdapter{
		bar:    p.userInterface.NewProgressBar(),
		logger: p.logger,
	}
}

type ProgressTrackerAdapter struct {
	bar    ui.ProgressBar
	logger *zerolog.Logger
}

func (p ProgressTrackerAdapter) Begin(title, message string) {
	if message == "" {
		p.bar.SetTitle(title + " - " + message)
	} else {
		p.bar.SetTitle(title)
	}

	err := p.bar.UpdateProgress(ui.InfiniteProgress)
	if err != nil {
		p.logger.Err(err).Msg("Failed to update progress")
	}
}

func (p ProgressTrackerAdapter) End(message string) {
	p.bar.SetTitle(message)
	err := p.bar.Clear()
	if err != nil {
		p.logger.Err(err).Msg("Failed to clear progress")
	}
}
