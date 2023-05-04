// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package e2e holds test suites for testing the fleet-server binary as a black box.
// It can be setup and ran with `make test-e2e` from the repo root dir.
package e2e

const binaryName = "fleet-server" //nolint:unused // work around to get platform specific binary name for tests
const agentName = "elastic-agent" //nolint:unused // work around to get platform specific binary name for tests
