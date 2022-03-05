// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

type Runtime struct {
	GCPercent int `config:"gc_percent"`
}

func (r Runtime) InitDefaults() {
	r.GCPercent = 0 //nolint
}
