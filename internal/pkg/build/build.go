// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package build

import "time"

const ServiceName = "fleet-server"

type Info struct {
	Version, Commit string
	BuildTime       time.Time
}

func Time(stime string) time.Time {
	t, err := time.Parse(time.RFC3339, stime)
	if err != nil {
		return time.Time{}
	}
	return t
}
