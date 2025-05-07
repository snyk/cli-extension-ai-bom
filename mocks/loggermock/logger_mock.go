package loggermock

import (
	"io"

	"github.com/rs/zerolog"
)

func NewNoOpLogger() *zerolog.Logger {
	logger := zerolog.New(io.Discard)
	return &logger
}
