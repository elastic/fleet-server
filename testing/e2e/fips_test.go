// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build e2e && requirefips

package e2e

import (
	"context"
	"debug/buildinfo"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/elastic/fleet-server/testing/e2e/scaffold"
	"github.com/elastic/fleet-server/v7/version"
)

type FIPSStandAlone struct {
	scaffold.Scaffold

	binaryPath string
}

func TestFIPSStandAlone(t *testing.T) {
	suite.Run(t, new(FIPSStandAlone))
}

func (suite *FIPSStandAlone) SetupSuite() {
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	}
	// NOTE the path checked is hardcoded to linux as we currently only support linux for FIPS builds
	path, err := filepath.Abs(filepath.Join("..", "..", "build", "cover", fmt.Sprintf("fleet-server-%s-SNAPSHOT-linux-%s-fips", version.DefaultVersion, arch), binaryName))
	suite.Require().NoError(err)
	suite.binaryPath = path
	_, err = os.Stat(suite.binaryPath)
	suite.Require().NoError(err)

	suite.Setup() // base setup
}

// TestVerifyArtifact verifies the artifact has FIPS indicators.
func (suite *FIPSStandAlone) TestVerifyArtifact() {
	info, err := buildinfo.ReadFile(suite.binaryPath)
	suite.Require().NoError(err)

	checkLinks := false
	foundTags := false
	foundExperiment := false
	for _, setting := range info.Settings {
		switch setting.Key {
		case "-tags":
			foundTags = true
			suite.Require().Contains(setting.Value, "requirefips")
			continue
		case "GOEXPERIMENT":
			foundExpirement = true
			suite.Require().Contains(setting.Value, "systemcrypto")
			continue
		case "-ldflags":
			if !strings.Contains(setting.Value, "-s") {
				checkLinks = true
				continue
			}
		}
	}

	suite.Require().True(t, foundTags, "Did not find -tags within binary description")
	suite.Require().True(t, foundExpirement, "Did not find GOEXPERIMENT within binary description")

	if checkLinks {
		suite.T().Log("checking artifact symbols")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "tool", "nm", suite.binaryPath) // TODO replace ctx with suite.T().Context() once we upgrade to go 1.24
		output, err := cmd.CombinedOutput()
		suite.Require().NoError(err)
		suite.Require().Contains(string(output), "OpenSSL_version", "Unable to find OpenSSL symbol links within binary")
	}
}
