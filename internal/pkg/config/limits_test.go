// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLimitValidate(t *testing.T) {
	t.Run("rejects negative Max", func(t *testing.T) {
		cfg := Limit{Max: -1}
		require.Error(t, cfg.Validate())
	})
	t.Run("accepts zero Max", func(t *testing.T) {
		cfg := Limit{Max: 0}
		require.NoError(t, cfg.Validate())
	})
	t.Run("accepts positive Max", func(t *testing.T) {
		cfg := Limit{Max: 100}
		require.NoError(t, cfg.Validate())
	})
}
