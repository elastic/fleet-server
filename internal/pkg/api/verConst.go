// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !snapshot

package api

import (
	"fmt"

	"github.com/hashicorp/go-version"
)

// BuildVersionConstraint turns the version into a constraint to ensure that the connecting Elastic Agent's are
// a supported version.
func BuildVersionConstraint(verStr string) (version.Constraints, error) {
	ver, err := version.NewVersion(verStr)
	if err != nil {
		return nil, err
	}
	verStr = maximizePatch(ver)
	return version.NewConstraint(fmt.Sprintf(">= %s, <= %s", MinVersion, verStr))
}
