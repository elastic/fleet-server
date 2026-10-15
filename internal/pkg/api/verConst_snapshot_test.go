// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

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
		// The default snapshot ceiling is exactly the next minor, not every patch of it.
		version: "8.1.1",
		succeed: false,
	}, {
		version: "8.2.0",
		succeed: false,
	}}

	for _, tc := range tests {
		t.Run(tc.version, func(t *testing.T) {
			vc, _, err := BuildVersionConstraint("8.0.0", "")
			require.NoError(t, err)
			ver, err := version.NewVersion(tc.version)
			require.NoError(t, err)

			require.Equalf(t, tc.succeed, vc.Check(ver), "vc is %s", vc.String())
		})
	}
}

func TestVersionConstraintOverride(t *testing.T) {
	const defaultConstraint = ">= 7.13, <= 8.1.0"

	tests := []struct {
		name       string
		override   string
		applied    bool
		constraint string
		accept     []string
		reject     []string
	}{{
		name:     "minor override",
		override: "8.3",
		applied:  true,
		accept:   []string{"8.1.0", "8.3.0", "8.3.5"},
		reject:   []string{"8.4.0"},
	}, {
		// The override is maximized before it is compared to the default, so it still
		// relaxes the ceiling when it has the same MAJOR.MINOR as the default.
		name:     "override at default minor accepts all patches",
		override: "8.1",
		applied:  true,
		accept:   []string{"8.1.5"},
		reject:   []string{"8.2.0"},
	}, {
		name:       "override below default is ignored",
		override:   "7.17",
		constraint: defaultConstraint,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vc, applied, err := BuildVersionConstraint("8.0.0", tc.override)
			require.NoError(t, err)
			require.Equal(t, tc.applied, applied)
			if tc.constraint != "" {
				require.Equal(t, tc.constraint, vc.String())
			}
			for _, v := range tc.accept {
				require.Truef(t, vc.Check(version.Must(version.NewVersion(v))), "%s should be accepted, constraint is %s", v, vc.String())
			}
			for _, v := range tc.reject {
				require.Falsef(t, vc.Check(version.Must(version.NewVersion(v))), "%s should be rejected, constraint is %s", v, vc.String())
			}
		})
	}

	t.Run("invalid override", func(t *testing.T) {
		_, _, err := BuildVersionConstraint("8.0.0", "8.six")
		require.Error(t, err)
	})

	t.Run("override with higher major is rejected", func(t *testing.T) {
		_, _, err := BuildVersionConstraint("8.0.0", "9.0")
		require.Error(t, err)
	})
}
