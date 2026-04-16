// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build snapshot

package ver

import (
	"testing"

	"github.com/stretchr/testify/require"

	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
)

func TestCheckCompatibilityInternal(t *testing.T) {
	tests := []struct {
		name         string
		fleetVersion string
		esVersion    string
	}{
		{
			name:         "empty fleet and elasticsearch version",
			fleetVersion: "",
			esVersion:    "",
		},
		{
			name:         "same version",
			fleetVersion: "7.13.0",
			esVersion:    "7.13.0",
		},
		{
			name:         "new fleet-server patch",
			fleetVersion: "7.13.2",
			esVersion:    "7.13.1",
		},
		{
			name:         "new es minor",
			fleetVersion: "7.13.2",
			esVersion:    "7.14.2",
		},
		{
			name:         "new es major",
			fleetVersion: "7.15.2",
			esVersion:    "8.0.0",
		},
		{
			name:         "new fleet-server minor",
			fleetVersion: "7.14.0",
			esVersion:    "7.13.1",
		},
		{
			name:         "new fleet-server major",
			fleetVersion: "8.0.0",
			esVersion:    "7.18.0",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testlog.SetLogger(t).WithContext(t.Context())
			err := checkCompatibility(ctx, tc.fleetVersion, tc.esVersion)
			require.NoError(t, err, "expected snapshot version check should always succeed")
		})
	}
}
