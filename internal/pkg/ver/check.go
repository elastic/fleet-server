// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package ver

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	esh "github.com/elastic/fleet-server/v7/internal/pkg/es"

	"github.com/hashicorp/go-version"
	"github.com/rs/zerolog/log"

	"github.com/elastic/go-elasticsearch/v7"
)

var (
	ErrUnsupportedVersion = errors.New("unsupported version")
	ErrMalformedVersion   = errors.New("malformed version")
)

func CheckCompatibility(ctx context.Context, esCli *elasticsearch.Client, fleetVersion string) (string, error) {
	log.Debug().Str("fleet_version", fleetVersion).Msg("check version compatibility with elasticsearch")

	esVersion, err := esh.FetchESVersion(ctx, esCli)

	if err != nil {
		log.Error().Err(err).Msg("failed to fetch elasticsearch version")
		return "", err
	}
	log.Debug().Str("elasticsearch_version", esVersion).Msg("fetched elasticsearch version")

	return esVersion, checkCompatibility(fleetVersion, esVersion)
}

func checkCompatibility(fleetVersion, esVersion string) error {
	verConst, err := buildVersionConstraint(fleetVersion)
	if err != nil {
		log.Error().Err(err).Str("fleet_version", fleetVersion).Msg("failed to build constraint")
		return err
	}

	ver, err := parseVersion(esVersion)
	if err != nil {
		return err
	}

	if !verConst.Check(ver) {
		log.Error().
			Err(ErrUnsupportedVersion).
			Str("constraint", verConst.String()).
			Str("reported", ver.String()).
			Msg("failed elasticsearch version check")
		return ErrUnsupportedVersion
	}
	log.Info().Str("fleet_version", fleetVersion).Str("elasticsearch_version", esVersion).Msg("Elasticsearch compatibility check successful")
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
		return nil, fmt.Errorf("%v: %w", err, ErrMalformedVersion)
	}
	return ver, nil
}
