// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration && !snapshot

package api

import (
	"testing"

	"github.com/hashicorp/go-version"
	"github.com/stretchr/testify/require"
)

func TestBuildVersionConstraint(t *testing.T) {
	const defaultConstraint = ">= 7.13, <= 9.4.2147483647"

	tests := []struct {
		name     string
		override string
		applied  bool
		accept   []string
		reject   []string
		// constraint, when set, pins the exact constraint string.
		constraint string
	}{{
		name:       "no override",
		override:   "",
		constraint: defaultConstraint,
		accept:     []string{"9.4.0", "9.4.7"},
		reject:     []string{"9.5.0"},
	}, {
		name:     "minor override",
		override: "9.6",
		applied:  true,
		accept:   []string{"9.4.0", "9.5.0", "9.6.0", "9.6.3"},
		reject:   []string{"9.7.0", "10.0.0", "7.12.0"},
	}, {
		// A .0 patch override is equivalent to the MAJOR.MINOR form: every 9.6.x is accepted, 9.7 and 10 are not.
		name:     "override with zero patch accepts all patches",
		override: "9.6.0",
		applied:  true,
		accept:   []string{"9.6.0", "9.6.3"},
		reject:   []string{"9.7.0", "10.0.0"},
	}, {
		name:     "override with patch accepts all patches",
		override: "9.6.1",
		applied:  true,
		accept:   []string{"9.6.0", "9.6.9"},
		reject:   []string{"9.7.0"},
	}, {
		name:       "override below default is ignored",
		override:   "9.3",
		constraint: defaultConstraint,
	}, {
		name:       "override equal to default is ignored",
		override:   "9.4",
		constraint: defaultConstraint,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vc, applied, err := BuildVersionConstraint("9.4.0", tc.override)
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
		_, _, err := BuildVersionConstraint("9.4.0", "9.six")
		require.Error(t, err)
	})

	t.Run("override with higher major is rejected", func(t *testing.T) {
		for _, o := range []string{"10.0", "10", "99", "10.0.0"} {
			_, _, err := BuildVersionConstraint("9.4.0", o)
			require.Errorf(t, err, "override %q", o)
		}
	})

	t.Run("invalid server version", func(t *testing.T) {
		_, _, err := BuildVersionConstraint("bad", "")
		require.Error(t, err)
	})
}
