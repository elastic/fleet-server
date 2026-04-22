// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build e2e && !requirefips

package e2e

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/elastic/fleet-server/testing/e2e/scaffold"
	"github.com/elastic/fleet-server/v7/version"

	"github.com/stretchr/testify/suite"
)

// NOTE: GOCOVERDIR is specied when manipulating the agent, but is not defined in the fleet-server spec and is not passed to fleet-server

type AgentInstallSuite struct {
	scaffold.Scaffold

	installDetected bool   // Flag to skip tests if an agent is detected
	agentPath       string // path to extracted elastic-agent binary (or symlink)
	binaryPath      string // path to compiled fleet-server
	downloadPath    string // path to unarchived downloaded elastic-agent package

}

func TestAgentInstallSuite(t *testing.T) {
	suite.Run(t, new(AgentInstallSuite))
}

func (suite *AgentInstallSuite) SetupSuite() {
	if runtime.GOOS == "windows" {
		suite.T().Skip("windows install e2e tests non-functional") // TODOO: https://github.com/elastic/fleet-server/issues/3620
		return
	}
	// check if agent is installed
	if _, err := exec.LookPath(agentDevName); err == nil {
		suite.installDetected = true
		return // don't bother with setup, skip all tests
	}
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	}
	if runtime.GOOS == "darwin" && arch == "arm64" {
		arch = "aarch64"
	}

	suite.Setup() // base setup
	suite.SetupKibana()

	// find compiled fleet-server
	path, err := filepath.Abs(filepath.Join("..", "..", "build", "cover", fmt.Sprintf("fleet-server-%s-SNAPSHOT-%s-%s", version.DefaultVersion, runtime.GOOS, arch), binaryName))
	suite.Require().NoError(err)
	suite.binaryPath = path
	_, err = os.Stat(suite.binaryPath)
	suite.Require().NoError(err)

	// setup context - timeline is for file download
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*10)
	defer cancel()

	// use artifacts API to download snapshot
	rc := downloadElasticAgent(ctx, suite.T(), suite.Client)
	defer rc.Close()

	// Unarchive download in temp dir
	suite.downloadPath = filepath.Join(os.TempDir(), "e2e-agent_install_test")
	err = os.MkdirAll(suite.downloadPath, 0755)
	suite.Require().NoError(err)
	var paths extractedPaths
	switch runtime.GOOS {
	case "windows":
		paths = extractZip(suite.T(), rc, suite.downloadPath)
	case "darwin", "linux":
		paths = extractTar(suite.T(), rc, suite.downloadPath)
	default:
		suite.Require().Failf("Unsupported OS", "OS %s is unsupported for tests", runtime.GOOS)
	}

	// Replace the fleet-server binary from the archive with the locally compiled version.
	if paths.fleetServerBinary != "" {
		suite.copyFleetServer(paths.fleetServerBinary)
	}

	suite.agentPath = paths.agentBinary
	_, err = os.Stat(suite.agentPath)
	suite.Require().NoError(err)
	suite.T().Log("Setup complete.")
}

func (suite *AgentInstallSuite) copyFleetServer(destPath string) {
	suite.T().Helper()
	src, err := os.Open(suite.binaryPath)
	suite.Require().NoError(err)
	defer src.Close()

	w, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	suite.Require().NoError(err)

	_, err = io.Copy(w, src)
	suite.Require().NoError(err)

	err = w.Close()
	suite.Require().NoError(err)
}

func (suite *AgentInstallSuite) TearDownSuite() {
	if suite.downloadPath != "" {
		// FIXME work around for needing to run sudo elastic-agent install
		err := exec.Command("sudo", "rm", "-rf", suite.downloadPath).Run()
		if err != nil {
			suite.T().Logf("unable to remove %q: %v", suite.downloadPath, err)
		}
	}
}

func (suite *AgentInstallSuite) SetupTest() {
	if suite.installDetected {
		suite.T().Skip("elastic-agent install detected, skipping test.")
	}

	portFree := suite.IsFleetServerPortFree()
	suite.Require().True(portFree, "port 8220 must not be in use for test to start")
}

func (suite *AgentInstallSuite) TearDownTest() {
	if suite.T().Skipped() {
		return
	}

	out, err := exec.Command("sudo", "elastic-development-agent", "uninstall", "--force").CombinedOutput()
	suite.Assert().NoErrorf(err, "elastic-development-agent uninstall failed. Output: %s", out)
}

func (suite *AgentInstallSuite) TestHTTP() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*3)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sudo", suite.agentPath, "install",
		"--develop", "--install-servers",
		"--fleet-server-es=http://"+suite.ESHosts,
		"--fleet-server-service-token="+suite.ServiceToken,
		"--fleet-server-insecure-http=true",
		"--fleet-server-host=0.0.0.0",
		"--fleet-server-policy=fleet-server-policy",
		"--non-interactive")
	cmd.Env = []string{"GOCOVERDIR=" + suite.CoverPath}
	cmd.Dir = filepath.Dir(suite.agentPath)

	output, err := cmd.CombinedOutput()
	suite.Require().NoErrorf(err, "elastic-agent install failed. command: %s, exit_code: %d, output: %s", cmd.String(), cmd.ProcessState.ExitCode(), string(output))

	suite.FleetServerStatusOK(ctx, "http://localhost:8220")
}

func (suite *AgentInstallSuite) TestWithSecretFiles() {
	dir := suite.T().TempDir()
	err := os.WriteFile(filepath.Join(dir, "service-token"), []byte(suite.ServiceToken), 0600)
	suite.Require().NoError(err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*3)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sudo", suite.agentPath, "install",
		"--develop", "--install-servers",
		"--url=https://localhost:8220",
		"--certificate-authorities="+filepath.Join(suite.CertPath, "e2e-test-ca.crt"),
		"--fleet-server-es=http://"+suite.ESHosts,
		"--fleet-server-service-token-path="+filepath.Join(dir, "service-token"),
		"--fleet-server-policy=fleet-server-policy",
		"--fleet-server-cert="+filepath.Join(suite.CertPath, "fleet-server.crt"),
		"--fleet-server-cert-key="+filepath.Join(suite.CertPath, "fleet-server.key"),
		"--fleet-server-cert-key-passphrase="+filepath.Join(suite.CertPath, "passphrase"),
		"--non-interactive")
	cmd.Env = []string{"GOCOVERDIR=" + suite.CoverPath}
	cmd.Dir = filepath.Dir(suite.agentPath)

	output, err := cmd.CombinedOutput()
	suite.Require().NoErrorf(err, "elastic-agent install failed. command: %s, exit_code: %d, output: %s", cmd.String(), cmd.ProcessState.ExitCode(), string(output))

	suite.FleetServerStatusOK(ctx, "https://localhost:8220")
}

func (suite *AgentInstallSuite) TestAPMInstrumentationFile() {
	suite.T().Skip("Testcase requires https://github.com/elastic/fleet-server/issues/3526 to be resolved.") // solution to 3526 may also resolve for the install test case, if it does not we can consider this to be an unsupported usecase and remove the test.
	// Restore original elastic-agent.yml after test
	cfgFile := filepath.Join(filepath.Dir(suite.agentPath), "elastic-agent.yml")
	f, err := os.Open(cfgFile)
	suite.Require().NoError(err)
	p, err := io.ReadAll(f)
	suite.Require().NoError(err)
	err = f.Close()
	suite.Require().NoError(err)
	err = os.Remove(cfgFile)
	suite.Require().NoError(err)
	suite.T().Cleanup(func() {
		f, err := os.OpenFile(cfgFile, os.O_RDWR|os.O_TRUNC, 0644)
		suite.Require().NoError(err)
		n, err := f.WriteAt(p, 0)
		suite.Require().NoError(err)
		err = f.Truncate(int64(n))
		suite.Require().NoError(err)
	})

	// write elastic-agent.yml used for test
	tpl, err := template.ParseFiles(filepath.Join("testdata", "agent-install-apm.tpl"))
	suite.Require().NoError(err)
	f, err = os.Create(cfgFile)
	suite.Require().NoError(err)
	err = tpl.Execute(f, map[string]string{
		"APMHost":  "http://localhost:8200",
		"TestName": "AgentInstallAPMInstrumentationFile",
	})
	f.Close()
	suite.Require().NoError(err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sudo", suite.agentPath, "install",
		"--develop", "--install-servers",
		"--fleet-server-es=http://"+suite.ESHosts,
		"--fleet-server-service-token="+suite.ServiceToken,
		"--fleet-server-insecure-http=true",
		"--fleet-server-host=0.0.0.0",
		"--fleet-server-policy=fleet-server-policy",
		"--non-interactive")
	cmd.Env = []string{"GOCOVERDIR=" + suite.CoverPath}
	cmd.Dir = filepath.Dir(suite.agentPath)

	output, err := cmd.CombinedOutput()
	suite.Require().NoErrorf(err, "elastic-agent install failed. command: %s, exit_code: %d, output: %s", cmd.String(), cmd.ProcessState.ExitCode(), string(output))

	suite.FleetServerStatusOK(ctx, "http://localhost:8220")
	suite.HasTestStatusTrace(ctx, "AgentInstallAPMInstrumentationFile", nil)
}

func (suite *AgentInstallSuite) TestAPMInstrumentationPolicy() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
	defer cancel()

	suite.AddPolicyOverrides(ctx, "fleet-server-apm", map[string]any{
		// NOTE: if the following key is specified as agent.monitoring the kibana ui will not merge it correctly in the policy.
		"agent": map[string]any{
			"monitoring": map[string]any{
				"traces": true,
				"apm": map[string]any{
					"hosts":        []any{"http://localhost:8200"},
					"environment":  "test-AgentInstallAPMInstrumentationPolicy",
					"secret_token": "b!gS3cret",
					"global_labels": map[string]any{
						"testName": "AgentInstallAPMInstrumentationPolicy",
					},
				},
			},
		},
	})

	cmd := exec.CommandContext(ctx, "sudo", suite.agentPath, "install",
		"--develop", "--install-servers",
		"--fleet-server-es=http://"+suite.ESHosts,
		"--fleet-server-service-token="+suite.ServiceToken,
		"--fleet-server-insecure-http=true",
		"--fleet-server-host=0.0.0.0",
		"--fleet-server-policy=fleet-server-apm",
		"--non-interactive")
	cmd.Env = []string{"GOCOVERDIR=" + suite.CoverPath}
	cmd.Dir = filepath.Dir(suite.agentPath)

	output, err := cmd.CombinedOutput()
	suite.Require().NoErrorf(err, "elastic-agent install failed. command: %s, exit_code: %d, output: %s", cmd.String(), cmd.ProcessState.ExitCode(), string(output))

	suite.FleetServerStatusOK(ctx, "http://localhost:8220")
	suite.HasTestStatusTrace(ctx, "AgentInstallAPMInstrumentationPolicy", func(ctx context.Context) {
		suite.FleetServerStatusOK(ctx, "http://localhost:8220") // retry status API if no traces are found to allow the policy reload to propagate
	})
}
