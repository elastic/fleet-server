// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package log

import (
	"testing"

	"github.com/rs/zerolog"
)

// SetLogger will set zerolog's package level logger to the testing output and returns the logger
// loggest is set to debug level
func SetLogger(tb testing.TB) zerolog.Logger {
	tb.Helper()
	tw := zerolog.TestWriter{T: tb, Frame: 4}
	log := zerolog.New(tw).Level(zerolog.DebugLevel)
	return log
}
