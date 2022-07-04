// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package rnd provudes a non-crypto secure random generator to use with testing.
package rnd

import (
	"math/rand"
	"time"
)

const (
	charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// Rnd Sufficiently random generator for testing
type Rnd struct {
	r *rand.Rand
}

func New() *Rnd {
	return &Rnd{
		r: rand.New(rand.NewSource(time.Now().Unix())), //nolint: gosec // used for testing
	}
}

func (r *Rnd) Int(min, max int) int {
	return r.r.Intn(max-min) + min
}

func (r *Rnd) Bool() bool {
	n := r.r.Intn(2)
	return n != 0
}

func (r *Rnd) String(sz int) string {
	b := make([]byte, sz)
	for i := range b {
		b[i] = charset[r.r.Intn(len(charset))]
	}
	return string(b)
}

type OffsetDirection int

const (
	TimeBefore = iota
	TimeAfter
)

func (d OffsetDirection) String() string {
	return []string{"Before", "After"}[d]
}

func (r *Rnd) Time(tm time.Time, min, max int, units time.Duration, direction OffsetDirection) time.Time {
	n := r.Int(min, max)

	dur := time.Duration(n) * units

	if direction == TimeBefore {
		return tm.Add(-dur)
	}
	return tm.Add(dur)
}
