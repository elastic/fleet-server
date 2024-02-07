// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

import "time"

const (
	defaultFetchSize          = 1000
	defaultPollTimeout        = 4 * time.Minute
	defaultPolicyDebounceTime = time.Second
)

type Monitor struct {
	FetchSize          int           `config:"fetch_size"`
	PollTimeout        time.Duration `config:"poll_timeout"`
	PolicyDebounceTime time.Duration `config:"policy_debounce_time"`
}

func (m *Monitor) InitDefaults() {
	m.FetchSize = defaultFetchSize
	m.PollTimeout = defaultPollTimeout
	m.PolicyDebounceTime = defaultPolicyDebounceTime
}
