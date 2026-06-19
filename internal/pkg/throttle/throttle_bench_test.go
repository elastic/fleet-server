// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package throttle

import (
	"testing"
	"time"

	"github.com/rs/zerolog"
)

var benchSinkToken Token

const benchKey = "agent-sha256-deadbeef"

// BenchmarkThrottleAcquire measures the Acquire implementation returning (Token, bool) by value.
// Token is returned by value; escape analysis can keep it on the stack.
func BenchmarkThrottleAcquire(b *testing.B) {
	log := zerolog.Nop()
	tt := NewThrottle(0) // zero max = unlimited parallel
	b.ReportAllocs()
	for b.Loop() {
		tok, ok := tt.Acquire(log, benchKey, time.Hour)
		if !ok {
			b.Fatal("Acquire returned false")
		}
		tok.Release(log)
		benchSinkToken = tok
	}
}
