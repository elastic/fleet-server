// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

import (
	"os"
	"path/filepath"
)

const (
	defaultPGPUpstreamURL   = "https://artifacts.elastic.co/GPG-KEY-elastic-agent"
	defaultPGPDirectoryName = "elastic-agent-upgrade-keys"
)

type PGP struct {
	// UpstreamURL is the URL to retrieve the default PGP upgrade key if it can't be found in Dir
	UpstreamURL string `config:"upstream_url"`
	// Dir is the location on disk where fleet-server will look for or store PGP keys.
	// By default it will be the [executable directory]/elastic-agent-upgrade-keys // TODO verify that this is a sane path for fleet-server in an elastic-agent container.
	Dir string `config:"dir"`
}

func (p *PGP) InitDefaults() {
	p.UpstreamURL = defaultPGPUpstreamURL
	p.Dir = filepath.Join(retrieveExecutableDir(), defaultPGPDirectoryName)
}

// retrieveExecutablePath returns the executing binary, even if the started binary was a symlink
// copied from elastic-agent/internal/pkg/agent/application/paths/common.go
func retrieveExecutableDir() string {
	execPath, err := os.Executable()
	if err != nil {
		panic(err)
	}
	evalPath, err := filepath.EvalSymlinks(execPath)
	if err != nil {
		panic(err)
	}
	return filepath.Dir(evalPath)
}
