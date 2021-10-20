// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/hashicorp/go-version"
	"github.com/rs/zerolog"
)

const (
	// MinVersion is the minimum version an Elastic Agent must be to communicate
	MinVersion = "7.13"

	userAgentPrefix = "elastic agent "
)

var (
	ErrInvalidUserAgent   = errors.New("user-agent is invalid")
	ErrUnsupportedVersion = errors.New("version is not supported")
)

// buildVersionConstraint turns the version into a constraint to ensure that the connecting Elastic Agent's are
// a supported version.
func buildVersionConstraint(verStr string) (version.Constraints, error) {
	ver, err := version.NewVersion(verStr)
	if err != nil {
		return nil, err
	}
	verStr = maximizePatch(ver)
	return version.NewConstraint(fmt.Sprintf(">= %s, <= %s", MinVersion, verStr))
}

// maximizePatch turns the version into a string that has the patch value set to the maximum integer.
//
// Used to allow the Elastic Agent to be at a higher patch version than the Fleet Server, but require that the
// Elastic Agent is not higher in MAJOR or MINOR.
func maximizePatch(ver *version.Version) string {
	segments := ver.Segments()
	if len(segments) > 2 {
		segments = segments[:2]
	}
	segments = append(segments, math.MaxInt32)
	segStrs := make([]string, 0, len(segments))
	for _, segment := range segments {
		segStrs = append(segStrs, strconv.Itoa(segment))
	}
	return strings.Join(segStrs, ".")
}

// validateUserAgent validates that the User-Agent of the connecting Elastic Agent is valid and that the version is
// supported for this Fleet Server.
func validateUserAgent(zlog zerolog.Logger, r *http.Request, verConst version.Constraints) (string, error) {
	userAgent := r.Header.Get("User-Agent")

	zlog = zlog.With().Str("userAgent", userAgent).Logger()

	if userAgent == "" {
		zlog.Info().
			Err(ErrInvalidUserAgent).
			Msg("empty User-Agent")
		return "", ErrInvalidUserAgent
	}

	userAgent = strings.ToLower(userAgent)
	if !strings.HasPrefix(userAgent, userAgentPrefix) {
		zlog.Info().
			Err(ErrInvalidUserAgent).
			Str("targetPrefix", userAgentPrefix).
			Msg("invalid user agent prefix")
		return "", ErrInvalidUserAgent
	}

	// Trim "elastic agent " prefix
	s := strings.TrimPrefix(userAgent, userAgentPrefix)

	// Split the version to accommodate versions with suffixes such as v8.0.0-snapshot v8.0.0-alpha1
	verSep := strings.Split(s, "-")

	// Trim leading and traling spaces
	verStr := strings.TrimSpace(verSep[0])

	ver, err := version.NewVersion(verStr)
	if err != nil {
		zlog.Info().
			Err(err).
			Str("verStr", verStr).
			Msg("invalid user agent version string")
		return "", ErrInvalidUserAgent
	}
	if !verConst.Check(ver) {
		zlog.Info().
			Err(ErrUnsupportedVersion).
			Str("verStr", verStr).
			Str("constraints", verConst.String()).
			Msg("unsuported user agent version")
		return "", ErrUnsupportedVersion
	}

	return ver.String(), nil
}
