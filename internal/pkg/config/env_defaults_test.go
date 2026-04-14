// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

import (
	"strconv"
	"testing"

	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadLimits(t *testing.T) {
	testCases := []struct {
		Name                 string
		ConfiguredAgentLimit int
		ExpectedAgentLimit   int
	}{
		{"default", -1, int(getMaxInt())},
		{"few agents", 5, 2500},
		{"512", 512, 2500},
		{"lesser bound", 5001, 10000},
		{"upper bound", 10000, 10000},
		{"above max", 40001, int(getMaxInt())},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			log := testlog.SetLogger(t)
			zerolog.DefaultContextLogger = &log
			l := loadLimits(&log, tc.ConfiguredAgentLimit)

			require.Equal(t, tc.ExpectedAgentLimit, l.Agents.Max)
		})
	}
}

func TestDefaultLimitsYAMLKeys(t *testing.T) {
	// Verify that all embedded YAML files have keys matching the Go struct tags.
	// A key typo (e.g. "pgp_retieval_limit" instead of "pgp_retrieval_limit")
	// causes the value to silently fall back to hardcoded defaults.
	require.NotEmpty(t, defaults, "embedded defaults should be loaded")
	for _, l := range defaults {
		name := "default"
		if l.Agents.Max > 0 && l.Agents.Max < int(getMaxInt()) {
			name = "lte" + strconv.Itoa(l.Agents.Max)
		}
		t.Run(name, func(t *testing.T) {
			require.NotNil(t, l.Server)

			// Every YAML file should populate these limit fields with
			// non-zero values that differ from the hardcoded defaults,
			// proving the YAML key matched the struct tag.
			assert.NotZero(t, l.Server.CheckinLimit.Interval, "checkin_limit.interval should be set")
			assert.NotZero(t, l.Server.AckLimit.Interval, "ack_limit.interval should be set")
			assert.NotZero(t, l.Server.EnrollLimit.Interval, "enroll_limit.interval should be set")
			assert.NotZero(t, l.Server.ArtifactLimit.Interval, "artifact_limit.interval should be set")
			assert.NotZero(t, l.Server.StatusLimit.Interval, "status_limit.interval should be set")
			assert.NotZero(t, l.Server.PolicyLimit.Interval, "policy_limit.interval should be set")
			assert.NotZero(t, l.Server.ActionLimit.Interval, "action_limit.interval should be set")
			assert.NotZero(t, l.Server.UploadStartLimit.Interval, "upload_start_limit.interval should be set")
			assert.NotZero(t, l.Server.UploadEndLimit.Interval, "upload_end_limit.interval should be set")
			assert.NotZero(t, l.Server.UploadChunkLimit.Interval, "upload_chunk_limit.interval should be set")
			assert.NotZero(t, l.Server.DeliverFileLimit.Interval, "file_delivery_limit.interval should be set")
			assert.NotZero(t, l.Server.GetPGPKeyLimit.Interval, "pgp_retrieval_limit.interval should be set")
			assert.NotZero(t, l.Server.AuditUnenrollLimit.Interval, "audit_unenroll_limit.interval should be set")
		})
	}
}
