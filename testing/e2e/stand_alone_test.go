// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"html/template"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	toxiproxy "github.com/Shopify/toxiproxy/client"
	"github.com/stretchr/testify/suite"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/fleet-server/testing/e2e/api_version"
	"github.com/elastic/fleet-server/testing/e2e/scaffold"
	"github.com/elastic/fleet-server/v7/version"
)

type StandAloneBase struct {
	scaffold.Scaffold

	binaryPath string
}

func (suite *StandAloneBase) SetupSuite() {
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	}
	path, err := filepath.Abs(filepath.Join("..", "..", "build", "cover", fmt.Sprintf("fleet-server-%s-SNAPSHOT-%s-%s", version.DefaultVersion, runtime.GOOS, arch), binaryName))
	suite.Require().NoError(err)
	suite.binaryPath = path
	_, err = os.Stat(suite.binaryPath)
	suite.Require().NoError(err)

	suite.Setup()       // base setup
	suite.SetupKibana() // load the defender integration for artifacts endpoint testing
}

// StandAloneSuite mainly tests getting a stand-alone binary running with different configuration
type StandAloneSuite struct {
	StandAloneBase
}

func TestStandAloneRunningSuite(t *testing.T) {
	suite.Run(t, new(StandAloneSuite))
}

func (suite *StandAloneSuite) SetupSuite() {
	suite.StandAloneBase.SetupSuite()
}

func (suite *StandAloneSuite) SetupTest() {
	portFree := suite.IsFleetServerPortFree()
	suite.Require().True(portFree, "port 8220 must not be in use for test to start")
}

// TestHTTP ensures that a basic http configuration functions
func (suite *StandAloneSuite) TestHTTP() {
	// Create a config file from a template in the test temp dir
	dir := suite.T().TempDir()
	tpl, err := template.ParseFiles(filepath.Join("testdata", "stand-alone-http.tpl"))
	suite.Require().NoError(err)
	f, err := os.Create(filepath.Join(dir, "config.yml"))
	suite.Require().NoError(err)
	err = tpl.Execute(f, map[string]string{
		"Hosts":        suite.ESHosts,
		"ServiceToken": suite.ServiceToken,
	})
	f.Close()
	suite.Require().NoError(err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)

	// Run the fleet-server binary
	cmd := exec.CommandContext(ctx, suite.binaryPath, "-c", filepath.Join(dir, "config.yml"))
	cmd.Cancel = func() error {
		return cmd.Process.Signal(syscall.SIGTERM)
	}
	cmd.Env = []string{"GOCOVERDIR=" + suite.CoverPath}
	err = cmd.Start()
	suite.Require().NoError(err)

	suite.FleetServerStatusOK(ctx, "http://localhost:8220")
	cancel()
	cmd.Wait()
}

// TestWithElasticsearchConnectionFailures checks the behaviour of stand alone Fleet Server
// when Elasticsearch is not reachable.
func (suite *StandAloneSuite) TestWithElasticsearchConnectionFailures() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)

	proxy, err := suite.StartToxiproxy(ctx).CreateProxy("es", "localhost:0", suite.ESHosts)
	suite.Require().NoError(err)

	// Create a config file from a template in the test temp dir
	dir := suite.T().TempDir()
	tpl, err := template.ParseFiles(filepath.Join("testdata", "stand-alone-http.tpl"))
	suite.Require().NoError(err)
	f, err := os.Create(filepath.Join(dir, "config.yml"))
	suite.Require().NoError(err)
	err = tpl.Execute(f, map[string]string{
		"Hosts":        "http://" + proxy.Listen,
		"ServiceToken": suite.ServiceToken,
	})
	f.Close()
	suite.Require().NoError(err)

	// Run the fleet-server binary
	cmd := exec.CommandContext(ctx, suite.binaryPath, "-c", filepath.Join(dir, "config.yml"))
	cmd.Cancel = func() error {
		return cmd.Process.Signal(syscall.SIGTERM)
	}
	cmd.Env = []string{"GOCOVERDIR=" + suite.CoverPath}
	err = cmd.Start()
	suite.Require().NoError(err)

	// Wait to check that it is healthy.
	suite.FleetServerStatusIs(ctx, "http://localhost:8220", client.UnitStateHealthy)

	// Provoke timeouts and wait for the healthcheck to fail.
	_, err = proxy.AddToxic("force_timeout", "timeout", "upstream", 1.0, toxiproxy.Attributes{})
	suite.Require().NoError(err)
	suite.FleetServerStatusIs(ctx, "http://localhost:8220", client.UnitStateDegraded)

	// Recover the network and wait for the healthcheck to be healthy again.
	err = proxy.RemoveToxic("force_timeout")
	suite.Require().NoError(err)
	suite.FleetServerStatusIs(ctx, "http://localhost:8220", client.UnitStateHealthy)

	cancel()
	cmd.Wait()
}

// TestWithSecretFiles tests starting an HTTPS server using a service-token file, public/private keys + passphrase file.
func (suite *StandAloneSuite) TestWithSecretFiles() {
	// Create a service token file in the temp test dir
	dir := suite.T().TempDir()
	err := os.WriteFile(filepath.Join(dir, "service-token"), []byte(suite.ServiceToken), 0600)
	suite.Require().NoError(err)

	// Create a config file from a template in the test temp dir
	tpl, err := template.ParseFiles(filepath.Join("testdata", "stand-alone-secret-file.tpl"))
	suite.Require().NoError(err)
	f, err := os.Create(filepath.Join(dir, "config.yml"))
	suite.Require().NoError(err)
	err = tpl.Execute(f, map[string]string{
		"Hosts":            suite.ESHosts,
		"ServiceTokenPath": filepath.Join(dir, "service-token"),
		"CertPath":         filepath.Join(suite.CertPath, "fleet-server.crt"),
		"KeyPath":          filepath.Join(suite.CertPath, "fleet-server.key"),
		"PassphrasePath":   filepath.Join(suite.CertPath, "passphrase"),
	})
	f.Close()
	suite.Require().NoError(err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// Run the fleet-server binary, cancelling context should stop process
	cmd := exec.CommandContext(ctx, suite.binaryPath, "-c", filepath.Join(dir, "config.yml"))
	cmd.Cancel = func() error {
		return cmd.Process.Signal(syscall.SIGTERM)
	}
	cmd.Env = []string{"GOCOVERDIR=" + suite.CoverPath}
	err = cmd.Start()
	suite.Require().NoError(err)

	suite.FleetServerStatusOK(ctx, "https://localhost:8220")
	cancel()
	cmd.Wait()
}

// TestStaticTokenAuthentication tests using static token configuration.
// A call to the enroll endpoint is made with static token configuration to ensure functionality as well as a non-static token call.
func (suite *StandAloneSuite) TestStaticTokenAuthentication() {
	dir := suite.T().TempDir()
	tpl, err := template.ParseFiles(filepath.Join("testdata", "stand-alone-https.tpl"))
	suite.Require().NoError(err)
	f, err := os.Create(filepath.Join(dir, "config.yml"))
	suite.Require().NoError(err)
	err = tpl.Execute(f, map[string]interface{}{
		"Hosts":                    suite.ESHosts,
		"ServiceToken":             suite.ServiceToken,
		"CertPath":                 filepath.Join(suite.CertPath, "fleet-server.crt"),
		"KeyPath":                  filepath.Join(suite.CertPath, "fleet-server.key"),
		"PassphrasePath":           filepath.Join(suite.CertPath, "passphrase"),
		"StaticPolicyTokenEnabled": true,
		"StaticTokenKey":           "abcdefg",
		"StaticPolicyID":           "dummy-policy",
	})
	suite.Require().NoError(err)
	f.Close()

	bCtx, bCancel := context.WithCancel(context.Background())
	defer bCancel()
	suite.T().Log("testing fleet-server binary")
	// Run the fleet-server binary, cancelling context should stop process
	cmd := exec.CommandContext(bCtx, suite.binaryPath, "-c", filepath.Join(dir, "config.yml"))
	cmd.Cancel = func() error {
		return cmd.Process.Signal(syscall.SIGTERM)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = []string{"GOCOVERDIR=" + suite.CoverPath}
	err = cmd.Start()
	suite.Require().NoError(err)

	ctx, cancel := context.WithTimeout(bCtx, time.Minute)
	suite.FleetServerStatusOK(ctx, "https://localhost:8220")

	// echo -n "01234:abcdefg" | base64
	// the id does not matter, the key is the important part
	enrollmentToken := "MDEyMzQ6YWJjZGVmZw=="

	defer cancel()
	tester := api_version.NewClientAPITesterCurrent(
		suite.Scaffold,
		"https://localhost:8220",
		enrollmentToken,
	)
	tester.Enroll(ctx, enrollmentToken)

	// Make sure a normal token works here as well
	enrollmentToken = suite.GetEnrollmentTokenForPolicyID(ctx, "dummy-policy")
	tester = api_version.NewClientAPITesterCurrent(
		suite.Scaffold,
		"https://localhost:8220",
		enrollmentToken,
	)
	tester.Enroll(ctx, enrollmentToken)
}

// TestElasticsearch429OnStartup will check to ensure fleet-server functions as expected (does not crash)
// if Elasticsearch returns 429s on startup.
func (suite *StandAloneSuite) TestElasticsearch429OnStartup() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)

	// Create a proxy that returns 429s
	proxy := NewStatusProxy(suite.T(), 429)
	proxy.Enable()
	server := httptest.NewServer(proxy)

	// Create a config file from a template in the test temp dir
	dir := suite.T().TempDir()
	tpl, err := template.ParseFiles(filepath.Join("testdata", "stand-alone-http-proxy.tpl"))
	suite.Require().NoError(err)
	f, err := os.Create(filepath.Join(dir, "config.yml"))
	suite.Require().NoError(err)
	err = tpl.Execute(f, map[string]string{
		"Hosts":        suite.ESHosts,
		"ServiceToken": suite.ServiceToken,
		"Proxy":        server.URL,
	})
	f.Close()
	suite.Require().NoError(err)

	// Run the fleet-server binary
	cmd := exec.CommandContext(ctx, suite.binaryPath, "-c", filepath.Join(dir, "config.yml"))
	//cmd.Stderr = os.Stderr // NOTE: This can be uncommented to put out logs
	cmd.Cancel = func() error {
		return cmd.Process.Signal(syscall.SIGTERM)
	}
	cmd.Env = []string{"GOCOVERDIR=" + suite.CoverPath}
	suite.T().Log("Starting fleet-server")
	err = cmd.Start()
	suite.Require().NoError(err)

	// FIXME timeout to make sure fleet-server has started
	time.Sleep(5 * time.Second)
	suite.T().Log("Checking fleet-server status")
	// Wait to check that it is Starting.
	suite.FleetServerStatusIs(ctx, "http://localhost:8220", client.UnitStateStarting) // fleet-server returns 503:starting if upstream ES returns 429.

	// Disable proxy and ensure fleet-server recovers
	suite.T().Log("Disable proxy")
	proxy.Disable()
	suite.FleetServerStatusIs(ctx, "http://localhost:8220", client.UnitStateHealthy)

	cancel()
	cmd.Wait()
}

// TestElasticsearchTimeoutOnStartup will check to ensure fleet-server functions as expected (does not crash)
// if Elasticsearch times out on startup.
func (suite *StandAloneSuite) TestElasticsearchTimeoutOnStartup() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)

	proxy, err := suite.StartToxiproxy(ctx).CreateProxy("es", "localhost:0", suite.ESHosts)
	suite.Require().NoError(err)
	_, err = proxy.AddToxic("force_timeout", "timeout", "upstream", 1.0, toxiproxy.Attributes{})
	suite.Require().NoError(err)

	// Create a config file from a template in the test temp dir
	dir := suite.T().TempDir()
	tpl, err := template.ParseFiles(filepath.Join("testdata", "stand-alone-http.tpl"))
	suite.Require().NoError(err)
	f, err := os.Create(filepath.Join(dir, "config.yml"))
	suite.Require().NoError(err)
	err = tpl.Execute(f, map[string]string{
		"Hosts":        "http://" + proxy.Listen,
		"ServiceToken": suite.ServiceToken,
	})
	f.Close()
	suite.Require().NoError(err)

	// Run the fleet-server binary
	cmd := exec.CommandContext(ctx, suite.binaryPath, "-c", filepath.Join(dir, "config.yml"))
	cmd.Cancel = func() error {
		return cmd.Process.Signal(syscall.SIGTERM)
	}
	cmd.Env = []string{"GOCOVERDIR=" + suite.CoverPath}
	err = cmd.Start()
	suite.Require().NoError(err)

	// Provoke timeouts, fleet-server should be stuck in the starting state
	suite.FleetServerStatusIs(ctx, "http://localhost:8220", client.UnitStateStarting)

	// Recover the network and wait for the healthcheck to be healthy again.
	err = proxy.RemoveToxic("force_timeout")
	suite.Require().NoError(err)
	suite.FleetServerStatusIs(ctx, "http://localhost:8220", client.UnitStateHealthy)

	cancel()
	cmd.Wait()
}

func (suite *StandAloneSuite) TestAPMInstrumentation() {
	// Create a config file from a template in the test temp dir
	dir := suite.T().TempDir()
	tpl, err := template.ParseFiles(filepath.Join("testdata", "stand-alone-apm.tpl"))
	suite.Require().NoError(err)
	f, err := os.Create(filepath.Join(dir, "config.yml"))
	suite.Require().NoError(err)
	err = tpl.Execute(f, map[string]string{
		"Hosts":        suite.ESHosts,
		"ServiceToken": suite.ServiceToken,
		"APMHost":      "http://localhost:8200",
		"TestName":     "StandAloneAPMInstrumentation",
	})
	f.Close()
	suite.Require().NoError(err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*3)

	// Run the fleet-server binary
	cmd := exec.CommandContext(ctx, suite.binaryPath, "-c", filepath.Join(dir, "config.yml"))
	cmd.Cancel = func() error {
		return cmd.Process.Signal(syscall.SIGTERM)
	}
	cmd.Env = []string{"GOCOVERDIR=" + suite.CoverPath}
	err = cmd.Start()
	suite.Require().NoError(err)

	suite.FleetServerStatusOK(ctx, "http://localhost:8220")
	suite.HasTestStatusTrace(ctx, "StandAloneAPMInstrumentation", nil)

	cancel()
	cmd.Wait()
}
