// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build e2e

package e2e

import (
	"encoding/json"
	"flag"
	"io"
	"os"
	"testing"

	"github.com/testcontainers/testcontainers-go/wait"
)

var longFlag bool

func init() {
	flag.BoolVar(&longFlag, "long", false, "Run long tests.")
}

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(m.Run())
}

func containerWaitForHealthyStatus() *wait.HTTPStrategy {
	matcher := func(body io.Reader) bool {
		d, err := io.ReadAll(body)
		if err != nil {
			return false
		}
		var status struct {
			Status string `json:"status"`
		}
		err = json.Unmarshal(d, &status)
		if err != nil {
			return false
		}
		return status.Status == "HEALTHY"
	}
	return wait.ForHTTP("/api/status").
		WithResponseMatcher(matcher).
		WithAllowInsecure(true).
		WithPort("8220/tcp")
}
