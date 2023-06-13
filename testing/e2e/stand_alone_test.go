// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	toxiproxy "github.com/Shopify/toxiproxy/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/stretchr/testify/suite"

	"github.com/elastic/fleet-server/v7/version"
)

type StandAloneSuite struct {
	BaseE2ETestSuite

	binaryPath string
}

func TestStandAloneRunningSuite(t *testing.T) {
	suite.Run(t, new(StandAloneSuite))
}

func (suite *StandAloneSuite) SetupSuite() {
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	}
	path, err := filepath.Abs(filepath.Join("..", "..", "build", "cover", fmt.Sprintf("fleet-server-%s-SNAPSHOT-%s-%s", version.DefaultVersion, runtime.GOOS, arch), binaryName))
	suite.Require().NoError(err)
	suite.binaryPath = path
	_, err = os.Stat(suite.binaryPath)
	suite.Require().NoError(err)

	suite.Setup() // base setup
}

func (suite *StandAloneSuite) SetupTest() {
	portFree := suite.IsFleetServerPortFree()
	suite.Require().True(portFree, "port 8220 must not be in use for test to start")
}

func (suite *StandAloneSuite) TestHTTP() {
	// Create a config file from a template in the test temp dir
	dir := suite.T().TempDir()
	tpl, err := template.ParseFiles(filepath.Join("testdata", "stand-alone-http.tpl"))
	suite.Require().NoError(err)
	f, err := os.Create(filepath.Join(dir, "config.yml"))
	suite.Require().NoError(err)
	err = tpl.Execute(f, map[string]string{
		"Hosts":        suite.esHosts,
		"ServiceToken": suite.serviceToken,
	})
	f.Close()
	suite.Require().NoError(err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)

	// Run the fleet-server binary
	cmd := exec.CommandContext(ctx, suite.binaryPath, "-c", filepath.Join(dir, "config.yml"))
	cmd.Cancel = func() error {
		return cmd.Process.Signal(syscall.SIGTERM)
	}
	cmd.Env = []string{"GOCOVERDIR=" + suite.coverPath}
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

	proxy, err := suite.StartToxiproxy(ctx).CreateProxy("es", "localhost:0", suite.esHosts)
	suite.Require().NoError(err)

	// Create a config file from a template in the test temp dir
	dir := suite.T().TempDir()
	tpl, err := template.ParseFiles(filepath.Join("testdata", "stand-alone-http.tpl"))
	suite.Require().NoError(err)
	f, err := os.Create(filepath.Join(dir, "config.yml"))
	suite.Require().NoError(err)
	err = tpl.Execute(f, map[string]string{
		"Hosts":        "http://" + proxy.Listen,
		"ServiceToken": suite.serviceToken,
	})
	f.Close()
	suite.Require().NoError(err)

	// Run the fleet-server binary
	cmd := exec.CommandContext(ctx, suite.binaryPath, "-c", filepath.Join(dir, "config.yml"))
	cmd.Cancel = func() error {
		return cmd.Process.Signal(syscall.SIGTERM)
	}
	cmd.Env = []string{"GOCOVERDIR=" + suite.coverPath}
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
	err := os.WriteFile(filepath.Join(dir, "service-token"), []byte(suite.serviceToken), 0600)
	suite.Require().NoError(err)

	// Create a config file from a template in the test temp dir
	tpl, err := template.ParseFiles(filepath.Join("testdata", "stand-alone-secret-file.tpl"))
	suite.Require().NoError(err)
	f, err := os.Create(filepath.Join(dir, "config.yml"))
	suite.Require().NoError(err)
	err = tpl.Execute(f, map[string]string{
		"Hosts":            suite.esHosts,
		"ServiceTokenPath": filepath.Join(dir, "service-token"),
		"CertPath":         filepath.Join(suite.certPath, "fleet-server.crt"),
		"KeyPath":          filepath.Join(suite.certPath, "fleet-server.key"),
		"PassphrasePath":   filepath.Join(suite.certPath, "passphrase"),
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
	cmd.Env = []string{"GOCOVERDIR=" + suite.coverPath}
	err = cmd.Start()
	suite.Require().NoError(err)

	suite.FleetServerStatusOK(ctx, "https://localhost:8220")
	cancel()
	cmd.Wait()
}

// TestClientAPI run an HTTPS server and use the ClientAPITester which wraps the generated pkg/api client to test endpoints
func (suite *StandAloneSuite) TestClientAPI() {
	dir := suite.T().TempDir()
	tpl, err := template.ParseFiles(filepath.Join("testdata", "stand-alone-https.tpl"))
	suite.Require().NoError(err)
	f, err := os.Create(filepath.Join(dir, "config.yml"))
	suite.Require().NoError(err)
	err = tpl.Execute(f, map[string]string{
		"Hosts":          suite.esHosts,
		"ServiceToken":   suite.serviceToken,
		"CertPath":       filepath.Join(suite.certPath, "fleet-server.crt"),
		"KeyPath":        filepath.Join(suite.certPath, "fleet-server.key"),
		"PassphrasePath": filepath.Join(suite.certPath, "passphrase"),
	})
	f.Close()

	bCtx, bCancel := context.WithCancel(context.Background())
	defer bCancel()

	// Run the fleet-server binary, cancelling context should stop process
	cmd := exec.CommandContext(bCtx, suite.binaryPath, "-c", filepath.Join(dir, "config.yml"))
	cmd.Cancel = func() error {
		return cmd.Process.Signal(syscall.SIGTERM)
	}
	cmd.Env = []string{"GOCOVERDIR=" + suite.coverPath}
	err = cmd.Start()
	suite.Require().NoError(err)

	ctx, cancel := context.WithTimeout(bCtx, time.Minute)
	suite.FleetServerStatusOK(ctx, "https://localhost:8220")
	cancel()

	enrollmentKey := suite.GetEnrollmentTokenForPolicyID(bCtx, "dummy-policy")

	// Run subtests here
	suite.Run("test status unauthenicated", func() {
		ctx, cancel := context.WithCancel(bCtx)
		defer cancel()
		tester := &ClientAPITester{
			suite.Suite,
			ctx,
			suite.client,
			"https://localhost:8220",
		}
		tester.TestStatus("")
	})

	suite.Run("test status authenicated", func() {
		ctx, cancel := context.WithCancel(bCtx)
		defer cancel()
		tester := &ClientAPITester{
			suite.Suite,
			ctx,
			suite.client,
			"https://localhost:8220",
		}
		tester.TestStatus(enrollmentKey)
	})

	suite.Run("test enroll checkin ack", func() {
		ctx, cancel := context.WithCancel(bCtx)
		defer cancel()
		tester := &ClientAPITester{
			suite.Suite,
			ctx,
			suite.client,
			"https://localhost:8220",
		}

		suite.T().Log("test enrollment")
		agentID, agentKey := tester.TestEnroll(enrollmentKey)
		suite.VerifyAgentInKibana(ctx, agentID)

		suite.T().Logf("test checkin 1: agent %s", agentID)
		ackToken, actions := tester.TestCheckin(agentKey, agentID, nil, nil)
		suite.Require().NotEmpty(actions)

		suite.T().Log("test ack")
		tester.TestAcks(agentKey, agentID, actions)

		suite.T().Logf("test checkin 2: agent %s 3m timout", agentID)
		dur := "3m"
		tester.ctx, cancel = context.WithTimeout(ctx, 3*time.Minute)
		defer cancel()

		tester.TestCheckin(agentKey, agentID, ackToken, &dur)

		// sanity check agent status in kibana
		suite.AgentIsOnline(ctx, agentID)
	})

	suite.Run("test file upload", func() {
		ctx, cancel := context.WithCancel(bCtx)
		defer cancel()
		tester := &ClientAPITester{
			suite.Suite,
			ctx,
			suite.client,
			"https://localhost:8220",
		}
		agentID, agentKey := tester.TestEnroll(enrollmentKey)
		actionID := suite.RequestDiagnosticsForAgent(ctx, agentID)

		tester.TestFullFileUpload(agentKey, agentID, actionID, 8192) // 8KiB file
	})

	suite.Run("test artifact", func() {
		ctx, cancel := context.WithTimeout(bCtx, 3*time.Minute)
		defer cancel()
		tester := &ClientAPITester{
			suite.Suite,
			ctx,
			suite.client,
			"https://localhost:8220",
		}
		_, agentKey := tester.TestEnroll(enrollmentKey)
		suite.AddSecurityContainer(ctx)
		suite.AddSecurityContainerItem(ctx)

		hits := suite.FleetHasArtifacts(ctx)
		tester.TestArtifact(agentKey, hits[0].Source.Identifier, hits[0].Source.DecodedSHA256, hits[0].Source.EncodedSHA256)
	})

	bCancel()
	cmd.Wait()
}
