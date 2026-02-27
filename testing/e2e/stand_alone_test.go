// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build e2e && !requirefips

package e2e

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	toxiproxy "github.com/Shopify/toxiproxy/v2/client"
	"github.com/stretchr/testify/suite"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/fleet-server/pkg/api"
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
	if runtime.GOOS == "darwin" && arch == "arm64" {
		arch = "aarch64"
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

	proxyContainer := suite.StartToxiproxy(ctx)
	proxyEndpoint, err := proxyContainer.URI(ctx)
	suite.Require().NoError(err)
	proxyClient := toxiproxy.NewClient(proxyEndpoint)

	pHost, pPort, err := proxyContainer.ProxiedEndpoint(8666) // Toxiproxy port starts at 8666
	suite.Require().NoError(err)

	// Create a config file from a template in the test temp dir
	dir := suite.T().TempDir()
	tpl, err := template.ParseFiles(filepath.Join("testdata", "stand-alone-http.tpl"))
	suite.Require().NoError(err)
	f, err := os.Create(filepath.Join(dir, "config.yml"))
	suite.Require().NoError(err)
	err = tpl.Execute(f, map[string]string{
		"Hosts":        fmt.Sprintf("http://%s:%s", pHost, pPort),
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
	proxy, err := proxyClient.Proxy("es")
	suite.Require().NoError(err)
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

// TestWithElasticsearchConnectionFlakyness checks the behaviour of stand alone Fleet Server
// when Elasticsearch is not reachable portion of the time.
func (suite *StandAloneSuite) TestWithElasticsearchConnectionFlakyness() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)

	proxyContainer := suite.StartToxiproxy(ctx)
	proxyEndpoint, err := proxyContainer.URI(ctx)
	suite.Require().NoError(err)
	proxyClient := toxiproxy.NewClient(proxyEndpoint)

	pHost, pPort, err := proxyContainer.ProxiedEndpoint(8666) // Toxiproxy port starts at 8666
	suite.Require().NoError(err)

	// Create a config file from a template in the test temp dir
	dir := suite.T().TempDir()
	tpl, err := template.ParseFiles(filepath.Join("testdata", "stand-alone-http.tpl"))
	suite.Require().NoError(err)
	f, err := os.Create(filepath.Join(dir, "config.yml"))
	suite.Require().NoError(err)
	err = tpl.Execute(f, map[string]string{
		"Hosts":        fmt.Sprintf("http://%s:%s", pHost, pPort),
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
	proxy, err := proxyClient.Proxy("es")
	suite.Require().NoError(err)
	suite.FleetServerStatusIs(ctx, "http://localhost:8220", client.UnitStateHealthy)

	// Provoke timeouts and wait for the healthcheck to fail.
	_, err = proxy.AddToxic("force_timeout", "timeout", "upstream", 0.4, toxiproxy.Attributes{}) // we have 5 retries, test with failure 4 out of 10 should be ok
	suite.Require().NoError(err)

	// wait for unit state degraded
	timeoutCtx, tCancel := context.WithTimeout(ctx, 30*time.Second)
	suite.FleetServerStatusNeverBecomes(timeoutCtx, "http://localhost:8220", client.UnitStateDegraded)

	// test should not fail at this point
	tCancel()

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

// TestElasticsearch503OnStartup will check to ensure fleet-server functions as expected (does not crash)
// if Elasticsearch returns 503s on startup.
func (suite *StandAloneSuite) TestElasticsearch503OnStartup() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)

	// Create a proxy that returns 503s
	proxy := NewStatusProxy(suite.T(), http.StatusServiceUnavailable)
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

// TestElasticsearch503OnEnroll will check to ensure fleet-server returns a 503 error when elasticsearch returns a
// 503 gateway error.
func (suite *StandAloneSuite) TestElasticsearch503OnEnroll() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)

	// Create a proxy that returns 503s
	proxy := NewStatusProxy(suite.T(), http.StatusServiceUnavailable)
	proxy.Disable() // start off
	server := httptest.NewServer(proxy)

	// Create a config file from a template in the test temp dir
	dir := suite.T().TempDir()
	tpl, err := template.ParseFiles(filepath.Join("testdata", "stand-alone-http-proxy.tpl"))
	suite.Require().NoError(err)
	f, err := os.Create(filepath.Join(dir, "config.yml"))
	suite.Require().NoError(err)
	err = tpl.Execute(f, map[string]any{
		"Hosts":                    suite.ESHosts,
		"ServiceToken":             suite.ServiceToken,
		"Proxy":                    server.URL,
		"StaticPolicyTokenEnabled": true,
		"StaticTokenKey":           "abcdefg",
		"StaticPolicyID":           "dummy-policy",
	})
	f.Close()
	suite.Require().NoError(err)

	// Run the fleet-server binary
	cmd := exec.CommandContext(ctx, suite.binaryPath, "-c", filepath.Join(dir, "config.yml"))
	cmd.Stderr = os.Stderr // NOTE: This can be uncommented to put out logs
	cmd.Cancel = func() error {
		return cmd.Process.Signal(syscall.SIGTERM)
	}
	cmd.Env = []string{"GOCOVERDIR=" + suite.CoverPath}
	suite.T().Log("Starting fleet-server")
	err = cmd.Start()
	suite.Require().NoError(err)
	defer func() {
		cancel()
		cmd.Wait()
	}()

	// FIXME timeout to make sure fleet-server has started
	time.Sleep(5 * time.Second)
	suite.T().Log("Checking fleet-server status")
	// Should start healthy as the proxy is disabled.
	suite.FleetServerStatusIs(ctx, "http://localhost:8220", client.UnitStateHealthy)

	// Ensure enrollment works correctly
	suite.T().Log("Checking enrollment works")
	enrollmentToken := suite.GetEnrollmentTokenForPolicyID(ctx, "dummy-policy")
	tester := api_version.NewClientAPITesterCurrent(
		suite.Scaffold,
		"http://localhost:8220",
		enrollmentToken,
	)
	tester.Enroll(ctx, enrollmentToken)

	// Enable the proxy which will cause enrollment to fail
	suite.T().Log("Force 503 error from proxy")
	proxy.Enable()

	// Perform enrollment again should error with 503
	suite.T().Log("Perform enrollment again")
	client, err := api.NewClientWithResponses("http://localhost:8220", api.WithHTTPClient(tester.Client), api.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "ApiKey "+enrollmentToken)
		return nil
	}))
	tester.Require().NoError(err)
	enrollResp, err := client.AgentEnrollWithResponse(ctx,
		&api.AgentEnrollParams{UserAgent: "elastic agent " + version.DefaultVersion},
		api.AgentEnrollJSONRequestBody{
			Type: api.PERMANENT,
		},
	)
	tester.Require().NoError(err)
	tester.Require().Equal(http.StatusServiceUnavailable, enrollResp.StatusCode())
}

// TestElasticsearchTimeoutOnStartup will check to ensure fleet-server functions as expected (does not crash)
// if Elasticsearch times out on startup.
func (suite *StandAloneSuite) TestElasticsearchTimeoutOnStartup() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)

	proxyContainer := suite.StartToxiproxy(ctx)
	proxyEndpoint, err := proxyContainer.URI(ctx)
	suite.Require().NoError(err)
	proxyClient := toxiproxy.NewClient(proxyEndpoint)
	proxy, err := proxyClient.Proxy("es")
	suite.Require().NoError(err)
	_, err = proxy.AddToxic("force_timeout", "timeout", "upstream", 1.0, toxiproxy.Attributes{})
	suite.Require().NoError(err)

	pHost, pPort, err := proxyContainer.ProxiedEndpoint(8666) // Toxiproxy port starts at 8666
	suite.Require().NoError(err)

	// Create a config file from a template in the test temp dir
	dir := suite.T().TempDir()
	tpl, err := template.ParseFiles(filepath.Join("testdata", "stand-alone-http.tpl"))
	suite.Require().NoError(err)
	f, err := os.Create(filepath.Join(dir, "config.yml"))
	suite.Require().NoError(err)
	err = tpl.Execute(f, map[string]string{
		"Hosts":        fmt.Sprintf("http://%s:%s", pHost, pPort),
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

// TestOpAMP ensures that the OpAMP endpoint in Fleet Server works as expected by installing
// an OTel Collector, configuring it with the OpAMP extension, and having it connect to Fleet
// Server using OpAMP, and verifying that Fleet Server responds to this request with an HTTP
// 200 OK status response.
func (suite *StandAloneSuite) TestOpAMP() {
	// Create a config file from a template in the test temp dir
	dir := suite.T().TempDir()
	tpl, err := template.ParseFiles(filepath.Join("testdata", "stand-alone-opamp.tpl"))
	suite.Require().NoError(err)
	f, err := os.Create(filepath.Join(dir, "config.yml"))
	suite.Require().NoError(err)
	err = tpl.Execute(f, map[string]interface{}{
		"Hosts":          suite.ESHosts,
		"ServiceToken":   suite.ServiceToken,
		"StaticTokenKey": "opamp-e2e-test-key",
	})
	f.Close()
	suite.Require().NoError(err)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Run the fleet-server binary
	cmd := exec.CommandContext(ctx, suite.binaryPath, "-c", filepath.Join(dir, "config.yml"))
	cmd.Cancel = func() error {
		return cmd.Process.Signal(syscall.SIGTERM)
	}
	cmd.Env = []string{"GOCOVERDIR=" + suite.CoverPath}
	err = cmd.Start()
	suite.Require().NoError(err)
	defer cmd.Wait()

	suite.FleetServerStatusOK(ctx, "http://localhost:8220")

	apiKey := suite.GetEnrollmentTokenForPolicyID(ctx, "dummy-policy")

	// Make sure the OpAMP endpoint works.
	req, err := http.NewRequestWithContext(ctx, "POST", "http://localhost:8220/v1/opamp", nil)
	suite.Require().NoError(err)
	req.Header.Set("Authorization", "ApiKey "+apiKey)
	req.Header.Set("Content-Type", "application/x-protobuf")

	resp, err := suite.Client.Do(req)
	suite.Require().NoError(err)
	resp.Body.Close()
	suite.Require().Equal(http.StatusOK, resp.StatusCode)

	// Enroll a dummy agent to initialize the .fleet-agents index before the OTel Collector connects.
	// Without this, findEnrolledAgent fails with index_not_found_exception when the OTel Collector
	// sends its first AgentToServer message, because .fleet-agents doesn't exist yet in a fresh
	// standalone fleet-server environment (unlike agent-managed fleet-server which self-enrolls).
	tester := api_version.NewClientAPITesterCurrent(suite.Scaffold, "http://localhost:8220", apiKey)
	tester.Enroll(ctx, apiKey)

	// Clone OTel Collector contrib repository (shallow clone of main branch)
	cloneDir := filepath.Join(dir, "opentelemetry-collector-contrib")
	suite.T().Logf("Cloning opentelemetry-collector-contrib (main) to %s", cloneDir)
	cloneCmd := exec.CommandContext(ctx,
		"git", "clone",
		"--depth", "1",
		"https://github.com/open-telemetry/opentelemetry-collector-contrib",
		cloneDir,
	)
	cloneCmd.Stdout = os.Stdout
	cloneCmd.Stderr = os.Stderr
	err = cloneCmd.Run()
	suite.Require().NoError(err)

	// Build the OTel Collector binary
	suite.T().Log("Building otelcol-contrib binary via make otelcontribcol")
	makeCmd := exec.CommandContext(ctx, "make", "otelcontribcol")
	makeCmd.Dir = cloneDir
	makeCmd.Stdout = os.Stdout
	makeCmd.Stderr = os.Stderr
	err = makeCmd.Run()
	suite.Require().NoError(err)

	// The make target places the binary under bin/; move it to the expected path.
	builtBinary := filepath.Join(cloneDir, "bin", fmt.Sprintf("otelcontribcol_%s_%s", runtime.GOOS, runtime.GOARCH))
	otelBinaryPath := filepath.Join(dir, "otelcol-contrib")
	err = os.Rename(builtBinary, otelBinaryPath)
	suite.Require().NoError(err)

	// Configure it with the OpAMP extension
	instanceUID := "019b8d7a-2da8-7657-b52d-492a9de33319"
	suite.T().Logf("Configuring OTel Collector with OpAMP extension (instanceUID=%s)", instanceUID)
	tpl, err = template.ParseFiles(filepath.Join("testdata", "otelcol-opamp.tpl"))
	suite.Require().NoError(err)
	f, err = os.Create(filepath.Join(dir, "otelcol.yml"))
	suite.Require().NoError(err)
	err = tpl.Execute(f, map[string]interface{}{
		"OpAMP": map[string]string{
			"InstanceUID": instanceUID,
			"APIKey":      apiKey,
		},
	})
	f.Close()
	suite.Require().NoError(err)

	// Start OTel Collector
	suite.T().Log("Starting OTel Collector")
	otelCmd := exec.CommandContext(ctx, otelBinaryPath, "--config", filepath.Join(dir, "otelcol.yml"))
	otelCmd.Cancel = func() error {
		return otelCmd.Process.Signal(syscall.SIGTERM)
	}
	otelCmd.Stdout = os.Stdout
	otelCmd.Stderr = os.Stderr
	err = otelCmd.Start()
	suite.Require().NoError(err)
	defer otelCmd.Wait()

	// Verify that the OTel Collector was enrolled in Fleet by fetching its document from
	// .fleet-agents and asserting on its contents.
	suite.T().Logf("Waiting for agent %s to appear in .fleet-agents", instanceUID)
	agentDoc := suite.WaitForAgentDoc(ctx, instanceUID)

	suite.Equal(instanceUID, agentDoc.Agent.ID, "expected agent.id to match instanceUID")
	versionOut, err := exec.Command(otelBinaryPath, "--version").Output()
	suite.Require().NoError(err)
	otelVersion := strings.TrimPrefix(strings.TrimSpace(string(versionOut)), "otelcontribcol version ")
	suite.Equal("OPAMP", agentDoc.Type, "expected type to be OPAMP")
	suite.Equal("otelcontribcol", agentDoc.Agent.Type, "expected agent.type to be otelcontribcol")
	suite.Equal(otelVersion, agentDoc.Agent.Version, "expected agent.version to match otelcol-contrib binary version")
	suite.Equal(1, agentDoc.Revision, "expected policy_revision_idx to be 1")
	suite.Contains(agentDoc.Tags, "otelcontribcol", "expected tags to contain otelcontribcol")
	suite.Equal("online", agentDoc.Status, "expected status to be online")
}
