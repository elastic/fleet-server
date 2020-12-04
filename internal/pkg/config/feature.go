// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

const (
	FeatureActions = "actions"
)

type Features map[string]Feature

func (f Features) Enabled(name string) bool {
	if feature, ok := f[name]; ok {
		return feature.Enabled
	}
	return false
}

type Feature struct {
	Enabled bool `config:"enabled"`
}
