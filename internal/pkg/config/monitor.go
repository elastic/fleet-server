// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

const (
	defaultFetchSize = 1000
)

type Monitor struct {
	FetchSize int `config:"fetch_size"`
}

func (m *Monitor) InitDefaults() {
	m.FetchSize = defaultFetchSize
}
