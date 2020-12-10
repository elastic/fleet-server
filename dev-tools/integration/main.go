// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"context"
	"fleet/internal/pkg/config"
	"fleet/internal/pkg/es"
	"fleet/internal/pkg/esboot"
	"fmt"
)

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

// Setup for integration testing
// Create the indices and data streams
func main() {
	fmt.Println("Setting up the indices")

	cfg, err := config.LoadFile("fleet-server.yml")
	checkErr(err)

	ctx := context.Background()
	es, err := es.NewClient(ctx, cfg)
	checkErr(err)

	err = esboot.EnsureESIndices(ctx, es)
	checkErr(err)
}
