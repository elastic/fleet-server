// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build e2e

package e2e

import (
	"context"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/elastic/fleet-server/testing/e2e/api_version"

	"github.com/stretchr/testify/suite"
)

type StandAloneCurrentAPI struct {
	StandAloneAPIBase
	api_version.ClientAPITester
}

func (suite *StandAloneCurrentAPI) SetupSuite() {
	suite.StandAloneAPIBase.SetupSuite()
	suite.SetEndpoint(suite.endpoint)
	suite.SetKey(suite.key)
}

type StandAlone20230601API struct {
	StandAloneAPIBase
	api_version.ClientAPITester20230601
}

func (suite *StandAlone20230601API) SetupSuite() {
	suite.StandAloneAPIBase.SetupSuite()
	suite.SetEndpoint(suite.endpoint)
	suite.SetKey(suite.key)
}

func TestStandAloneCurrentAPI(t *testing.T) {
	s := new(StandAloneCurrentAPI)
	s.ClientAPITester.Scaffold = &s.StandAloneAPIBase.StandAloneBase.Scaffold

	suite.Run(t, s)
}

func TestStandAlone20230601API(t *testing.T) {
	s := new(StandAlone20230601API)
	s.ClientAPITester20230601.Scaffold = &s.StandAloneAPIBase.StandAloneBase.Scaffold

	suite.Run(t, s)
}

/*
 *  API Testing boilerplate below
 */

type StandAloneAPIBase struct {
	StandAloneBase

	cancel   context.CancelFunc
	cmd      *exec.Cmd
	endpoint string
	key      string
}

// SetupSuite will run a stand-alone fleet-server instance as an HTTPS server with secret files.
func (suite *StandAloneAPIBase) SetupSuite() {
	suite.StandAloneBase.SetupSuite()

	// make sure we can bind to port
	portFree := suite.IsFleetServerPortFree()
	suite.Require().True(portFree, "port 8220 must not be in use for test to start")

	// Start fleet-server
	dir := suite.T().TempDir()
	tpl, err := template.ParseFiles(filepath.Join("testdata", "stand-alone-https.tpl"))
	suite.Require().NoError(err)
	f, err := os.Create(filepath.Join(dir, "config.yml"))
	suite.Require().NoError(err)
	err = tpl.Execute(f, map[string]string{
		"Hosts":          suite.ESHosts,
		"ServiceToken":   suite.ServiceToken,
		"CertPath":       filepath.Join(suite.CertPath, "fleet-server.crt"),
		"KeyPath":        filepath.Join(suite.CertPath, "fleet-server.key"),
		"PassphrasePath": filepath.Join(suite.CertPath, "passphrase"),
	})
	f.Close()

	ctx, cancel := context.WithCancel(context.Background())
	suite.cancel = cancel

	// Run the fleet-server binary, cancelling context should stop process
	cmd := exec.CommandContext(ctx, suite.binaryPath, "-c", filepath.Join(dir, "config.yml"))
	cmd.Cancel = func() error {
		return cmd.Process.Signal(syscall.SIGTERM)
	}
	cmd.Env = []string{"GOCOVERDIR=" + suite.CoverPath}
	suite.T().Log("Starting fleet-server process")
	err = cmd.Start()
	suite.Require().NoError(err)
	suite.cmd = cmd

	rCtx, rCancel := context.WithTimeout(ctx, time.Minute)
	suite.FleetServerStatusOK(rCtx, "https://localhost:8220")
	rCancel()

	suite.key = suite.GetEnrollmentTokenForPolicyID(ctx, "dummy-policy")
	suite.endpoint = "https://localhost:8220"
}

func (suite *StandAloneAPIBase) TearDownSuite() {
	suite.T().Log("Stopping fleet-server process")
	suite.cancel()
	suite.cmd.Wait()
}
