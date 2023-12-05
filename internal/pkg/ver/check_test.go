// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package ver

import (
	"context"
	"errors"
	"testing"

	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
)

func TestCheckCompatibilityInternal(t *testing.T) {
	tests := []struct {
		name         string
		fleetVersion string
		esVersion    string
		err          error
	}{
		{
			name:         "empty fleet and elasticsearch version",
			fleetVersion: "",
			esVersion:    "",
			err:          ErrMalformedVersion,
		},
		{
			name:         "empty fleet version",
			fleetVersion: "",
			esVersion:    "8.0.0",
			err:          ErrMalformedVersion,
		},
		{
			name:         "empty elasticsearch version",
			fleetVersion: "7.13",
			esVersion:    "",
			err:          ErrMalformedVersion,
		},
		{
			name:         "supported elasticsearch 713-713",
			fleetVersion: "7.13.0",
			esVersion:    "7.13.0",
			err:          nil,
		},
		{
			name:         "supported elasticsearch 7131-7132",
			fleetVersion: "7.13.2",
			esVersion:    "7.13.1",
			err:          nil,
		},
		{
			name:         "supported elasticsearch 713-714",
			fleetVersion: "7.13.2",
			esVersion:    "7.14.2",
			err:          nil,
		},
		{
			name:         "supported elasticsearch 715-800",
			fleetVersion: "7.15.2",
			esVersion:    "8.0.0",
			err:          nil,
		},
		{
			name:         "unsupported elasticsearch 714-713",
			fleetVersion: "7.14.0",
			esVersion:    "7.13.1",
			err:          ErrUnsupportedVersion,
		},
		{
			name:         "unsupported elasticsearch 800-718",
			fleetVersion: "8.0.0",
			esVersion:    "7.18.0",
			err:          ErrUnsupportedVersion,
		},
		{
			name:         "supported elasticsearch 800a1",
			fleetVersion: "8.0.0-alpha1",
			esVersion:    "8.0.0-alpha1",
			err:          nil,
		},
		{
			name:         "supported elasticsearch 715-800a1",
			fleetVersion: "7.15.2",
			esVersion:    "8.0.0-alpha1",
			err:          nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testlog.SetLogger(t).WithContext(context.Background())
			err := checkCompatibility(ctx, tc.fleetVersion, tc.esVersion)
			if tc.err != nil {
				if err == nil {
					t.Error("expected error")
				} else {
					if !errors.Is(err, tc.err) {
						t.Errorf("unexpected error kind: %v", err)
					}
				}
			} else {
				if err != nil {
					t.Error("unexpected error")
				}
			}
		})
	}
}
