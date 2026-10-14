// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestReloadMetrics(t *testing.T) {
	t.Run("logs duration, phases and memory at debug level", func(t *testing.T) {
		var buf bytes.Buffer
		log := zerolog.New(&buf).Level(zerolog.DebugLevel)

		rm := startReloadMetrics(log)
		require.NotNil(t, rm)
		require.NoError(t, rm.measure("phaseA", func() error { return nil }))
		require.NoError(t, rm.measure("phaseA", func() error { return nil }))
		require.EqualError(t, rm.measure("phaseB", func() error { return errors.New("boom") }), "boom")
		rm.log(log, "hits", 2)

		var out map[string]any
		require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
		require.Equal(t, "Policy reload metrics", out["message"])
		require.Equal(t, "hits", out["trigger"])
		require.EqualValues(t, 2, out["nPolicies"])
		require.Contains(t, out, "durationMs")
		require.Contains(t, out, "heapUsedMbPeak")
		require.Contains(t, out, "totalMemoryMbPeak")
		require.Len(t, out["phaseDurationsMs"], 2)
	})

	t.Run("is a no-op when debug is disabled", func(t *testing.T) {
		var buf bytes.Buffer
		log := zerolog.New(&buf).Level(zerolog.InfoLevel)

		rm := startReloadMetrics(log)
		require.Nil(t, rm)
		require.NoError(t, rm.measure("phaseA", func() error { return nil }))
		rm.log(log, "hits", 1)
		require.Empty(t, buf.Bytes())
	})
}
