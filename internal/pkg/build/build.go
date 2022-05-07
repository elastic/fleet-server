// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package build contains build inforamtion that can be exposed during runtime.
package build

import "time"

const ServiceName = "fleet-server"

// Info contains build information.
type Info struct {
	Version, Commit string
	BuildTime       time.Time
}

// Time parses the given string using RFC3339, or returns an empty time.Time
func Time(stime string) time.Time {
	t, err := time.Parse(time.RFC3339, stime)
	if err != nil {
		return time.Time{}
	}
	return t
}
