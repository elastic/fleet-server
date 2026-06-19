// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package monitor

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMonitorTemplateTokenCounts ensures that all template variants constructed
// by simpleMonitorT stay within dsl.renderPairsCap. The templates are built at
// runtime (not at package init), so this test is the earliest point at which
// dsl.ErrTooManyTokens would be caught for this package.
func TestMonitorTemplateTokenCounts(t *testing.T) {
	tests := []struct {
		name           string
		withExpiration bool
	}{
		{name: "without expiration", withExpiration: false},
		{name: "with expiration", withExpiration: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := &simpleMonitorT{
				withExpiration: tc.withExpiration,
				fetchSize:      defaultFetchSize,
			}

			_, err := m.prepareCheckQuery()
			require.NoError(t, err, "prepareCheckQuery exceeds dsl.renderPairsCap")

			_, err = m.prepareQuery()
			require.NoError(t, err, "prepareQuery exceeds dsl.renderPairsCap")
		})
	}
}
