// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// +build !integration

package config

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
)

func TestBindAddress(t *testing.T) {
	testcases := map[string]struct {
		cfg    Server
		result string
	}{
		"localhost": {
			cfg: Server{
				Host: "localhost",
				Port: 5000,
			},
			result: "localhost:5000",
		},
		"ipv6": {
			cfg: Server{
				Host: "::1",
				Port: 6565,
			},
			result: "[::1]:6565",
		},
	}

	for name, test := range testcases {
		t.Run(name, func(t *testing.T) {
			res := test.cfg.BindAddress()
			if !assert.True(t, cmp.Equal(test.result, res)) {
				diff := cmp.Diff(test.result, res)
				if diff != "" {
					t.Errorf("%s mismatch (-want +got):\n%s", name, diff)
				}
			}
		})
	}
}
