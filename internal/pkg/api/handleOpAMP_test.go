// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"net/http"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
	"github.com/stretchr/testify/require"
)

func TestFeatureFlag(t *testing.T) {
	cases := map[string]struct {
		FeatureFlagEnabled bool
		WantError          error
	}{
		"feature flag is disabled": {
			FeatureFlagEnabled: false,
			WantError:          ErrOpAMPDisabled,
		},
		"feature flag is enabled": {
			FeatureFlagEnabled: true,
			WantError:          apikey.ErrNoAuthHeader,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := &config.Server{
				Features: config.FeatureFlags{
					EnableOpAMP: tc.FeatureFlagEnabled,
				},
			}

			logger := testlog.SetLogger(t)
			req := http.Request{}
			var resp http.ResponseWriter

			oa := OpAMPT{cfg: cfg}
			err := oa.handleOpAMP(logger, &req, resp)
			require.Equal(t, tc.WantError, err)
		})
	}
}
