// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Command dslcheck reports dsl.Tmpl variables with more than renderPairsCap
// Bind() calls in a single function body. Run as a vet plugin:
//
//	go build -o dslcheck ./dev-tools/static/cmd/dslcheck
//	go vet -vettool=./dslcheck ./...
//
// Or without building:
//
//	go run ./dev-tools/static/cmd/dslcheck ./...
package main

import (
	"golang.org/x/tools/go/analysis/singlechecker"

	"github.com/elastic/fleet-server/dev-tools/static/dslcheck"
)

func main() {
	singlechecker.Main(dslcheck.Analyzer)
}
