// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build snapshot

package api

import (
	"strconv"
	"strings"

	"github.com/hashicorp/go-version"
)

// defaultMaxVersion returns the highest agent version accepted by default.
// For snapshot builds we allow the minor version to be newer in order to allow automated testing to proceed.
func defaultMaxVersion(ver *version.Version) string {
	return bumpMinor(ver)
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
