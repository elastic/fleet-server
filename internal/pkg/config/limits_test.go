// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServerLimitsValidate(t *testing.T) {
	t.Run("rejects negative Max", func(t *testing.T) {
		cfg := ServerLimits{CheckinLimit: Limit{Max: -1}}
		err := cfg.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "checkin_limit")
	})
	t.Run("accepts zero Max", func(t *testing.T) {
		cfg := ServerLimits{CheckinLimit: Limit{Max: 0}}
		require.NoError(t, cfg.Validate())
	})
	t.Run("ignores Max on limits that do not use it", func(t *testing.T) {
		cfg := ServerLimits{ActionLimit: Limit{Max: -1}, PolicyLimit: Limit{Max: -1}}
		require.NoError(t, cfg.Validate())
	})
	t.Run("accepts positive Max", func(t *testing.T) {
		cfg := ServerLimits{CheckinLimit: Limit{Max: 100}}
		require.NoError(t, cfg.Validate())
	})
}
