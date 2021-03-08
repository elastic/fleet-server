// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package throttle

import (
	"math/rand"
	"strconv"
	"testing"
	"time"
)

func TestThrottleZero(t *testing.T) {

	// Zero max parallel means we can acquire as many as we want,
	// but still cannot acquire existing that has not timed out
	throttle := NewThrottle(0)

	N := rand.Intn(2048) + 10

	var tokens []*Token
	for i := 0; i < N; i++ {

		key := strconv.Itoa(i)

		// Acquire token for key with long timeout so doesn't trip unit test
		token1 := throttle.Acquire(key, time.Hour)
		if token1 == nil {
			t.Fatal("Acquire failed")
		}
		tokens = append(tokens, token1)

		// Second acquire should fail because we have not released the orginal token,
		// or possibly if i == N-1 we could max parallel
		token2 := throttle.Acquire(key, time.Hour)
		if token2 != nil {
			t.Error("Expected second acquire to fail on conflict")
		}
	}

	// Validate again that all tokens are blocked after allocating N
	for i := 0; i < N; i++ {

		key := strconv.Itoa(i)

		// Acquire should fail because we have not released the orginal token,
		token := throttle.Acquire(key, time.Hour)
		if token != nil {
			t.Error("Expected acquire to fail on conflict")
		}
	}

	for i, token := range tokens {

		found := token.Release()
		if !found {
			t.Error("Expect token to be found")
		}

		// Second release should return false
		found = token.Release()
		if found {
			t.Error("Expect token to not found on second release")
		}

		// We should now be able to to acquire
		key := strconv.Itoa(i)

		token = throttle.Acquire(key, time.Hour)
		if token == nil {
			t.Fatal("Acquire failed")
		}

		found = token.Release()
		if !found {
			t.Error("Expect token to be found")
		}
	}
}

func TestThrottleN(t *testing.T) {

	for N := 1; N < 11; N++ {

		throttle := NewThrottle(N)

		var tokens []*Token
		for i := 0; i < N; i++ {

			key := strconv.Itoa(i)

			// Acquire token for key with long timeout so doesn't trip unit test
			token1 := throttle.Acquire(key, time.Hour)
			if token1 == nil {
				t.Fatal("Acquire failed")
			}
			tokens = append(tokens, token1)

			// Second acquire should fail because we have not released the orginal token,
			// or possibly if i == N-1 we could max parallel
			token2 := throttle.Acquire(key, time.Hour)
			if token2 != nil {
				t.Error("Expected second acquire to fail on conflict")
			}
		}

		// Any subsequent request should fail because at max
		try := rand.Intn(1000) + 1
		for i := 0; i < try; i++ {

			key := strconv.Itoa(N + i)

			token1 := throttle.Acquire(key, time.Hour)
			if token1 != nil {
				t.Fatal("Expect acquire to fail on max tokens")
			}
		}

		// Release one at a time, validate that we can reacquire
		for i, token := range tokens {

			found := token.Release()
			if !found {
				t.Error("Expect token to be found")
			}

			// Second release should return false
			found = token.Release()
			if found {
				t.Error("Expect token to not found on second release")
			}

			// We should now be able to to acquire
			key := strconv.Itoa(i)

			token = throttle.Acquire(key, time.Hour)
			if token == nil {
				t.Fatal("Acquire failed")
			}

			found = token.Release()
			if !found {
				t.Error("Expect token to be found")
			}
		}
	}
}

func TestThrottleExpireIdentity(t *testing.T) {
	throttle := NewThrottle(1)

	key := "xxx"
	token := throttle.Acquire(key, time.Second)

	// Should *NOT* be able to re-acquire until TTL
	token2 := throttle.Acquire(key, time.Hour)
	if token2 != nil {
		t.Error("Expected second acquire to fail on conflict")
	}

	time.Sleep(time.Second)

	// Should be able to re-acquire on expiration
	token3 := throttle.Acquire(key, time.Hour)
	if token3 == nil {
		t.Error("Expected third aquire to succeed")
	}

	// Original token should fail release
	found := token.Release()
	if found {
		t.Error("Expected token to have expired")
	}

	// However, third token should release fine
	found = token3.Release()
	if !found {
		t.Error("Expect recently acquired token to release cleanly")
	}
}

// Test that a token from a different key is expired when at max
func TestThrottleExpireAtMax(t *testing.T) {
	throttle := NewThrottle(1)

	key1 := "xxx"
	token1 := throttle.Acquire(key1, time.Second)

	// Should be at max, cannot acquire different key
	key2 := "yyy"
	token2 := throttle.Acquire(key2, time.Hour)
	if token2 != nil {
		t.Error("Expected second acquire to fail on max")
	}

	time.Sleep(time.Second)

	// Should be able acquire second after timeout
	token2 = throttle.Acquire(key2, time.Hour)
	if token2 == nil {
		t.Error("Expected third aquire to succeed")
	}

	// Original token should fail release
	found := token1.Release()
	if found {
		t.Error("Expected token to have expired")
	}

	// However, third token should release fine
	found = token2.Release()
	if !found {
		t.Error("Expect recently acquired token2 to release cleanly")
	}
}
