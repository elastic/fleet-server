// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:generate schema-generate -esdoc -s -o internal/pkg/model/schema.go -p model model/schema.json
//go:generate go fmt internal/pkg/model/schema.go
//go:generate schema-generate -m es -o internal/pkg/es/mapping.go -p es model/schema.json
//go:generate go fmt internal/pkg/es/mapping.go

package main

import (
	"fmt"
	"os"

	"github.com/elastic/fleet-server/v7/cmd/fleet"
	"github.com/elastic/fleet-server/v7/internal/pkg/build"
)

const defaultVersion = "7.16.1"

var (
	Version   string = defaultVersion
	Commit    string
	BuildTime string
)

func main() {
	cmd := fleet.NewCommand(build.Info{
		Version:   Version,
		Commit:    Commit,
		BuildTime: build.Time(BuildTime),
	})
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
