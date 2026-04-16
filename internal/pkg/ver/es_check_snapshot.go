// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build snapshot

package ver

import (
	"context"

	"github.com/rs/zerolog"
)

func checkCompatibility(ctx context.Context, fleetVersion, esVersion string) error {
	zerolog.Ctx(ctx).Info().Str("fleet_version", fleetVersion).Str("elasticsearch_version", esVersion).Msg("SNAPSHOT build skipping Elasticsearch compatibility check")
	return nil
}
