// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			_ = testlog.SetLogger(t)
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

func TestRefresh(t *testing.T) {
	tests := []struct {
		name string
		err  string
	}{{
		name: "true",
		err:  "",
	}, {
		name: "false",
		err:  "",
	}, {
		name: "wait_for",
		err:  "",
	}, {
		name: "error",
		err:  ErrBulkerRefresh.Error(),
	}}
	fTemplate := `
inputs:
  - type: fleet-server
    server:
      bulk:
        refresh: "%s"
`

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yml")
			f, err := os.Create(path)
			require.NoError(t, err)
			_, err = fmt.Fprintf(f, fTemplate, tt.name)
			require.NoError(t, err)
			f.Close()

			cfg, err := LoadFile(path)
			if tt.err == "" {
				require.NoError(t, err)
				require.Equal(t, tt.name, cfg.Inputs[0].Server.Bulk.Refresh)
			} else {
				// Using ErrorContains here instead of ErrorIs as go-ucfg does not wrap errors correctly
				require.ErrorContains(t, err, tt.err)
			}

		})
	}
}
