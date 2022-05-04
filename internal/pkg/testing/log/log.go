package log

import (
	"testing"

	"github.com/rs/zerolog"
	zl "github.com/rs/zerolog/log"
)

// SetLogger will set zerolog's package level logger to the testing output and returns the logger
// loggest is set to debug level
func SetLogger(tb testing.TB) zerolog.Logger {
	tb.Helper()
	tw := zerolog.TestWriter{T: tb, Frame: 4}
	logger := zerolog.New(tw).Level(zerolog.DebugLevel)
	zl.Logger = logger
	return logger
}
