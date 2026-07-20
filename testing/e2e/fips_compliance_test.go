// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package e2e_test

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/elastic/elastic-agent-libs/testing/fipsscan"
)

// knownViolations maps component import paths to the reason they import a
// forbidden crypto library. An empty map is a strict gate: any new violation
// fails the test. Keys are the first-hop import from the binary package.
var knownViolations = map[string]string{}

// TestFIPSFullyCompliant discovers every package main in this module and
// verifies that none of its transitive dependencies import a forbidden
// (non-FIPS) crypto library. A new binary added to the module is automatically
// covered without any changes to this file.
func TestFIPSFullyCompliant(t *testing.T) {
	modOut, err := exec.CommandContext(t.Context(), "go", "list", "-m").Output()
	if err != nil {
		t.Fatalf("go list -m: %v", err)
	}
	module := strings.TrimSpace(string(modOut))

	out, err := exec.CommandContext(t.Context(), "go", "list",
		"-tags", "requirefips",
		"-f", `{{if eq .Name "main"}}{{.ImportPath}}{{end}}`,
		module+"/...",
	).Output()
	if err != nil {
		t.Fatalf("go list %s/...: %v", module, err)
	}

	binaries := strings.Fields(string(out))
	if len(binaries) == 0 {
		t.Skip("no package main in module — library-only module, nothing to scan")
	}

	for _, bin := range binaries {
		t.Run(bin, func(t *testing.T) {
			fipsscan.CheckViolations(t, bin, bin, nil, knownViolations)
		})
	}
}
