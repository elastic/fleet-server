//go:build !snapshot

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package ver will ensure fleet-server and Elasticsearch are running compatible versions.
// Versions are compatible when Elasticsearch's version is greater then or equal to fleet-server's version
package ver

import (
	"context"

	"github.com/rs/zerolog"
)

func checkCompatibility(ctx context.Context, fleetVersion, esVersion string) error {
	verConst, err := buildVersionConstraint(fleetVersion)
	if err != nil {
		zerolog.Ctx(ctx).Error().Err(err).Str("fleet_version", fleetVersion).Msg("failed to build constraint")
		return err
	}

	ver, err := parseVersion(esVersion)
	if err != nil {
		return err
	}

	if !verConst.Check(ver) {
		zerolog.Ctx(ctx).Error().
			Err(ErrUnsupportedVersion).
			Str("constraint", verConst.String()).
			Str("reported", ver.String()).
			Msg("failed elasticsearch version check")
		return ErrUnsupportedVersion
	}
	zerolog.Ctx(ctx).Info().Str("fleet_version", fleetVersion).Str("elasticsearch_version", esVersion).Msg("Elasticsearch compatibility check successful")
	return nil
}
