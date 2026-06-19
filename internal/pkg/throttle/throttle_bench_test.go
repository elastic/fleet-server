// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package throttle

import (
	"testing"
	"time"

	"github.com/rs/zerolog"
)

var benchSinkToken *Token

const benchKey = "agent-sha256-deadbeef"

// BenchmarkThrottleAcquirePointer measures the current Acquire returning *Token.
// The Token struct is heap-allocated on every successful acquire.
func BenchmarkThrottleAcquirePointer(b *testing.B) {
	log := zerolog.Nop()
	tt := NewThrottle(0) // zero max = unlimited parallel
	b.ReportAllocs()
	for b.Loop() {
		tok := tt.Acquire(log, benchKey, time.Hour)
		if tok == nil {
			b.Fatal("Acquire returned nil")
		}
		tok.Release(log)
		benchSinkToken = tok
	}
}

// acquireValue is the proposed implementation returning (Token, bool) by value,
// allowing the Token struct to be stack-allocated instead of heap-allocated.
func (tt *Throttle) acquireValue(log zerolog.Logger, key string, ttl time.Duration) (Token, bool) {
	tt.mut.Lock()
	defer tt.mut.Unlock()

	if tt.checkAtMaxPending(log, key) {
		return Token{}, false
	}

	state, ok := tt.tokenMap[key]
	now := time.Now()
	if !ok || state.expire.Before(now) {
		tt.tokenCnt++
		tok := Token{
			id:       tt.tokenCnt,
			key:      key,
			throttle: tt,
		}
		tt.tokenMap[key] = tstate{
			id:     tok.id,
			expire: now.Add(ttl),
		}
		return tok, true
	}
	return Token{}, false
}

var benchSinkTokenValue Token

// BenchmarkThrottleAcquireValue measures the proposed (Token, bool) return.
// Token is returned by value; escape analysis can keep it on the stack.
func BenchmarkThrottleAcquireValue(b *testing.B) {
	log := zerolog.Nop()
	tt := NewThrottle(0)
	b.ReportAllocs()
	for b.Loop() {
		tok, ok := tt.acquireValue(log, benchKey, time.Hour)
		if !ok {
			b.Fatal("acquireValue returned false")
		}
		tok.Release(log)
		benchSinkTokenValue = tok
	}
}
