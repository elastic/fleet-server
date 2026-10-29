// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package server

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
)

func Test_configChangedServer_FeatureFlagsService(t *testing.T) {
	log := testlog.SetLogger(t)
	cur := &config.Config{Inputs: []config.Input{{}}}

	assert.False(t, configChangedServer(log, cur, &config.Config{Inputs: []config.Input{{}}}))

	enabled := &config.Config{Inputs: []config.Input{{FeatureFlagsService: config.FeatureFlagsService{Enabled: true}}}}
	assert.True(t, configChangedServer(log, cur, enabled))

	cors := &config.Config{Inputs: []config.Input{{FeatureFlagsService: config.FeatureFlagsService{
		Enabled: true,
		CORS:    config.FeatureFlagsCORS{AllowedOrigins: []string{"https://app.example.com"}},
	}}}}
	assert.True(t, configChangedServer(log, enabled, cors))
}
