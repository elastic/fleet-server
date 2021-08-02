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
func validateUserAgent(r *http.Request, verConst version.Constraints) (string, error) {
	userAgent := r.Header.Get("User-Agent")
	if userAgent == "" {
		return "", ErrInvalidUserAgent
	}
	userAgent = strings.ToLower(userAgent)
	if !strings.HasPrefix(userAgent, userAgentPrefix) {
		return "", ErrInvalidUserAgent
	}

	// Trim "elastic agent " prefix
	s := strings.TrimPrefix(userAgent, userAgentPrefix)
	// Trim "-snapshot" suffix
	s = strings.TrimSuffix(s, "-snapshot")
	// Trim leading and traling spaces
	verStr := strings.TrimSpace(s)

	ver, err := version.NewVersion(verStr)
	if err != nil {
		return "", ErrInvalidUserAgent
	}
	if !verConst.Check(ver) {
		return "", ErrUnsupportedVersion
	}
	return ver.String(), nil
}
