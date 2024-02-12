// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package monitor

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubscribeChSize(t *testing.T) {
	tests := []struct {
		i   int
		exp int
	}{{
		i:   -1,
		exp: 1,
	}, {
		i:   0,
		exp: 1,
	}, {
		i:   1,
		exp: 1,
	}, {
		i:   2,
		exp: 2,
	}}

	sm := monitorT{
		subs:       make(map[uint64]*subT, 0),
		subTimeout: time.Second,
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("size %d", tc.i), func(t *testing.T) {
			s := sm.Subscribe(ChSize(tc.i))
			defer sm.Unsubscribe(s)
			sub, ok := s.(*subT)
			require.True(t, ok, "expected s to be a *subT")

			assert.Equal(t, tc.exp, cap(sub.c), "channel capacity does not match expected value")
		})
	}
}
