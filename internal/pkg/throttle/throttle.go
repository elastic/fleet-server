// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package throttle

import (
	"github.com/rs/zerolog/log"
	"sync"
	"time"
)

type Token struct {
	id       uint64
	key      string
	throttle *Throttle
}

type tstate struct {
	id     uint64
	expire time.Time
}

type Throttle struct {
	mut         sync.Mutex
	maxParallel int
	tokenCnt    uint64
	tokenMap    map[string]tstate
}

// Throttle provides two controls:
// 1) Only one Token per key at a time can be acquired.  Token expires if not released by ttl.
// 2) Only max unexpired tokens acquired at any one time.

func NewThrottle(max int) *Throttle {
	return &Throttle{
		maxParallel: max,
		tokenMap:    make(map[string]tstate),
	}
}

func (tt *Throttle) Acquire(key string, ttl time.Duration) *Token {
	var token *Token

	tt.mut.Lock()
	defer tt.mut.Unlock()

	if tt.checkAtMaxPending(key) {
		log.Trace().
			Str("key", key).
			Int("max", tt.maxParallel).
			Int("szMap", len(tt.tokenMap)).
			Msg("Throttle fail acquire on max pending")
		return nil
	}

	// Is there already a pending request on this key?
	state, ok := tt.tokenMap[key]

	// If there's nohting pending on 'key' or previous timed out create token

	now := time.Now()
	if !ok || state.expire.Before(now) {
		tt.tokenCnt += 1

		token = &Token{
			id:       tt.tokenCnt,
			key:      key,
			throttle: tt,
		}

		state := tstate{
			id:     token.id,
			expire: now.Add(ttl),
		}

		tt.tokenMap[key] = state

		log.Trace().
			Str("key", key).
			Uint64("token", token.id).
			Time("expire", state.expire).
			Msg("Throttle acquired")

		return token
	}

	log.Trace().
		Str("key", key).
		Msg("Throttle fail acquire on existing token")

	return token
}

// WARNING:  Assumes mutex already held
func (tt *Throttle) checkAtMaxPending(key string) bool {

	// Are we already at max parallel?
	if tt.maxParallel == 0 || len(tt.tokenMap) < tt.maxParallel {
		return false
	}

	now := time.Now()

	// Try to eject the target key first
	if state, ok := tt.tokenMap[key]; ok && state.expire.Before(now) {
		delete(tt.tokenMap, key)
		log.Trace().
			Str("key", key).
			Msg("Ejected target token on expiration")

		return false
	}

	// Scan through map looking for something to expire.
	// Not very efficient, O(N), but perhaps not worth optimizing
	var found bool
	for skey, state := range tt.tokenMap {
		if state.expire.Before(now) {
			found = true
			delete(tt.tokenMap, skey)
			log.Trace().
				Str("key", key).
				Msg("Ejected token on expiration")
			break
		}
	}

	return !found
}

func (tt *Throttle) release(id uint64, key string) bool {

	tt.mut.Lock()
	defer tt.mut.Unlock()

	state, ok := tt.tokenMap[key]
	if !ok {
		log.Trace().Uint64("id", id).Str("key", key).Msg("Token not found to release")
		return false
	}

	if state.id == id {
		log.Trace().Uint64("id", id).Str("key", key).Msg("Token released")
		delete(tt.tokenMap, key)
		return true
	}

	return false
}

func (t Token) Release() bool {
	return t.throttle.release(t.id, t.key)
}
