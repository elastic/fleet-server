// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

const kDefaultHTTPHost = "localhost"
const kDefaultHTTPPort = 5066

// Http is the configuration for the API endpoint.
type HTTP struct {
	Enabled            bool   `config:"enabled"`
	Host               string `config:"host"`
	Port               int    `config:"port"`
	User               string `config:"named_pipe.user"`
	SecurityDescriptor string `config:"named_pipe.security_descriptor"`
}

func (h *HTTP) InitDefaults() {
	h.Enabled = false
	h.Host = kDefaultHTTPHost
	h.Port = kDefaultHTTPPort
}
