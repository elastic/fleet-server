// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:generate schema-generate -s -o internal/pkg/model/schema.go -p model model/schema.json
//go:generate go fmt internal/pkg/model/schema.go
//go:generate schema-generate -m es -o internal/pkg/esboot/mapping.go -p esboot model/schema.json
//go:generate go fmt internal/pkg/esboot/mapping.go

package main

import (
	"fmt"
	"os"

	// Needed for the generator not to be nuked by go tidy. Fails make check otherwise.
	_ "github.com/aleksmaus/generate"

	"fleet/cmd/fleet"
)

var (
	Version string
)

func main() {
	cmd := fleet.NewCommand(Version)
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
