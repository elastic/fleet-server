// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build snapshot

package api

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/go-version"
)

// BuildVersionConstraint turns the version into a constraint to ensure that the connecting Elastic Agent's are
// a supported version.
// For snapshot builds we allow the minor version to be newer in order to allow automated testing to proceed.
func BuildVersionConstraint(verStr string) (version.Constraints, error) {
	ver, err := version.NewVersion(verStr)
	if err != nil {
		return nil, err
	}
	verStr = bumpMinor(ver)
	return version.NewConstraint(fmt.Sprintf(">= %s, <= %s", MinVersion, verStr))
}

// bumpMinor returns a version string where 1 is added to the minor version
func bumpMinor(ver *version.Version) string {
	segments := ver.Segments()
	if len(segments) < 2 {
		return ver.String()
	}
	segments[1] += 1
	strs := make([]string, 0, len(segments))
	for _, seg := range segments {
		strs = append(strs, strconv.Itoa(seg))
	}
	return strings.Join(strs, ".")
}
