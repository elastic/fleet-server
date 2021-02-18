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

	// Needed for the generator not to be nuked by go tidy. Fails make check otherwise.
	_ "github.com/aleksmaus/generate"

	"github.com/elastic/fleet-server/v7/cmd/fleet"
)

const defaultVersion = "7.13.0"

var (
	Version string = defaultVersion
)

func main() {
	cmd := fleet.NewCommand(Version)
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
