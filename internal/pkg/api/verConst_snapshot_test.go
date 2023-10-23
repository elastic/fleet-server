// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration && snapshot

package api

import (
	"testing"

	"github.com/hashicorp/go-version"
	"github.com/stretchr/testify/require"
)

func TestVersionConstraint(t *testing.T) {
	tests := []struct {
		version string
		succeed bool
	}{{
		version: "8.0.0",
		succeed: true,
	}, {
		version: "8.1.0",
		succeed: true,
	}, {
		version: "8.2.0",
		succeed: false,
	}}

	for _, tc := range tests {
		t.Run(tc.version, func(t *testing.T) {
			vc, err := BuildVersionConstraint("8.0.0")
			require.NoError(t, err)
			ver, err := version.NewVersion(tc.version)
			require.NoError(t, err)

			require.Equalf(t, tc.succeed, vc.Check(ver), "vc is %s", vc.String())
		})
	}
}
