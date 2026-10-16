// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !snapshot

package api

import (
	"github.com/hashicorp/go-version"
)

// defaultMaxVersion returns the highest agent version accepted by default: any patch of this MAJOR.MINOR.
func defaultMaxVersion(ver *version.Version) string {
	return maximizePatch(ver)
}
