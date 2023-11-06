// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package ver will ensure fleet-server and Elasticsearch are running compatible versions.
// Versions are compatible when Elasticsearch's version is greater then or equal to fleet-server's version
package ver

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	esh "github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/rs/zerolog"

	"github.com/hashicorp/go-version"

	"github.com/elastic/go-elasticsearch/v8"
)

// Variables to define errors when comparing versions.
var (
	ErrUnsupportedVersion = errors.New("unsupported version")
	ErrMalformedVersion   = errors.New("malformed version")
)

// CheckCompatiblility will check the remote Elasticsearch version retrieved by the Elasticsearch client with the passed fleet version.
// Versions are compatible when Elasticsearch's version is greater then or equal to fleet-server's version
func CheckCompatibility(ctx context.Context, esCli *elasticsearch.Client, fleetVersion string) (string, error) {
	zerolog.Ctx(ctx).Debug().Str("fleet_version", fleetVersion).Msg("check version compatibility with elasticsearch")

	esVersion, err := esh.FetchESVersion(ctx, esCli)

	if err != nil {
		zerolog.Ctx(ctx).Error().Err(err).Msg("failed to fetch elasticsearch version")
		return "", err
	}
	zerolog.Ctx(ctx).Debug().Str("elasticsearch_version", esVersion).Msg("fetched elasticsearch version")

	return esVersion, checkCompatibility(ctx, fleetVersion, esVersion)
}

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

func buildVersionConstraint(fleetVersion string) (version.Constraints, error) {
	ver, err := parseVersion(fleetVersion)
	if err != nil {
		return nil, err
	}
	return version.NewConstraint(fmt.Sprintf(">= %s", minimizePatch(ver)))
}

func minimizePatch(ver *version.Version) string {
	segments := ver.Segments()
	if len(segments) > 2 {
		segments = segments[:2]
	}
	segments = append(segments, 0)
	segStrs := make([]string, 0, len(segments))
	for _, segment := range segments {
		segStrs = append(segStrs, strconv.Itoa(segment))
	}
	return strings.Join(segStrs, ".")
}

func parseVersion(sver string) (*version.Version, error) {
	ver, err := version.NewVersion(strings.Split(sver, "-")[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", err, ErrMalformedVersion)
	}
	return ver, nil
}
