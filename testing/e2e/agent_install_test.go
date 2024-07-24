// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build e2e

package e2e

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/elastic/fleet-server/testing/e2e/scaffold"
	"github.com/elastic/fleet-server/v7/version"

	"github.com/stretchr/testify/suite"
)

type AgentInstallSuite struct {
	scaffold.Scaffold

	installDetected bool   // Flag to skip tests if an agent is detected
	agentPath       string // path to extracted elastic-agent binary (or symlink)
	binaryPath      string // path to compiled fleet-server
	downloadPath    string // path to unarchived downloaded elastic-agent package

}

// SearchResp is the response body for the artifacts search API
type SearchResp struct {
	Packages map[string]Artifact `json:"packages"`
}

// Artifact describes an elastic artifact available through the API.
type Artifact struct {
	URL string `json:"url"`
	//SHAURL       string `json:"sha_url"`      // Unused
	//Type         string `json:"type"`         // Unused
	//Architecture string `json:"architecture"` // Unused
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
	if _, err := exec.LookPath(agentName); err == nil {
		suite.installDetected = true
		return // don't bother with setup, skip all tests
	}
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
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
	rc := suite.downloadAgent(ctx)
	defer rc.Close()

	// Unarchive download in temp dir
	suite.downloadPath = filepath.Join(os.TempDir(), "e2e-agent_install_test")
	err = os.Mkdir(suite.downloadPath, 0755)
	suite.Require().NoError(err)
	switch runtime.GOOS {
	case "windows":
		suite.extractZip(rc)
	case "darwin", "linux":
		suite.extractTar(rc)
	default:
		suite.Require().Failf("Unsupported OS", "OS %s is unsupported for tests", runtime.GOOS)
	}
	_, err = os.Stat(suite.agentPath)
	suite.Require().NoError(err)
	suite.T().Log("Setup complete.")
}

// downloadAgent will search the artifacts repo for the latest snapshot and return the stream to the download for the current OS + ARCH.
func (suite *AgentInstallSuite) downloadAgent(ctx context.Context) io.ReadCloser {
	suite.T().Helper()
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://artifacts-api.elastic.co/v1/search/%s-SNAPSHOT", version.DefaultVersion), nil)
	suite.Require().NoError(err)

	resp, err := suite.Client.Do(req)
	suite.Require().NoError(err)

	var body SearchResp
	err = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	suite.Require().NoError(err)

	fType := "tar.gz"
	if runtime.GOOS == "windows" {
		fType = "zip"
	}

	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	}
	if arch == "arm64" && runtime.GOOS == "darwin" {
		arch = "aarch64"
	}

	fileName := fmt.Sprintf("elastic-agent-%s-SNAPSHOT-%s-%s.%s", version.DefaultVersion, runtime.GOOS, arch, fType)
	pkg, ok := body.Packages[fileName]
	suite.Require().True(ok, "unable to find package download")

	req, err = http.NewRequestWithContext(ctx, "GET", pkg.URL, nil)
	suite.Require().NoError(err)
	resp, err = suite.Client.Do(req)
	suite.Require().NoError(err)
	return resp.Body
}

// extractZip treats the passed Reader as a zip stream and unarchives it to a temp dir
// fleet-server binary in archive is replaced by a locally compiled version
func (suite *AgentInstallSuite) extractZip(r io.Reader) {
	suite.T().Helper()
	// Extract zip stream
	var b bytes.Buffer
	n, err := io.Copy(&b, r)
	suite.Require().NoError(err)
	zipReader, err := zip.NewReader(bytes.NewReader(b.Bytes()), n)
	suite.Require().NoError(err)
	for _, file := range zipReader.File {
		path := filepath.Join(suite.downloadPath, file.Name)
		mode := file.FileInfo().Mode()
		switch {
		case mode.IsDir():
			err := os.MkdirAll(path, 0755)
			suite.Require().NoError(err)
		case mode.IsRegular():
			err := os.MkdirAll(filepath.Dir(path), 0755)
			suite.Require().NoError(err)
			w, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
			suite.Require().NoError(err)
			if strings.HasSuffix(file.Name, binaryName) {
				suite.copyFleetServer(w)
				continue
			}
			if strings.HasSuffix(file.Name, agentName) {
				suite.agentPath = path
			}
			f, err := file.Open()
			suite.Require().NoError(err)
			_, err = io.Copy(w, f)
			suite.Require().NoError(err)
			err = w.Close()
			suite.Require().NoError(err)
			err = f.Close()
			suite.Require().NoError(err)
		default:
			suite.T().Logf("Unable to unzip type=%+v in file=%s", mode, path)
		}
	}
}

// extractTar treats the passed Reader as a tar.gz stream and unarchives it to the suite.downloadPath
// fleet-server binary in archive is replaced by a locally compiled version
func (suite *AgentInstallSuite) extractTar(r io.Reader) {
	suite.T().Helper()
	// Extract tar.gz stream
	gs, err := gzip.NewReader(r)
	suite.Require().NoError(err)
	tarReader := tar.NewReader(gs)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		suite.Require().NoError(err)

		path := filepath.Join(suite.downloadPath, header.Name)
		mode := header.FileInfo().Mode()
		switch {
		case mode.IsDir():
			err := os.MkdirAll(path, 0755)
			suite.Require().NoError(err)
		case mode.IsRegular():
			err := os.MkdirAll(filepath.Dir(path), 0755)
			suite.Require().NoError(err)
			w, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode.Perm())
			suite.Require().NoError(err)
			// Use local fleet-server instead of the one from the archive
			if strings.HasSuffix(header.Name, binaryName) {
				suite.copyFleetServer(w)
				continue
			}
			_, err = io.Copy(w, tarReader)
			suite.Require().NoError(err)
			err = w.Close()
			suite.Require().NoError(err)
		case mode.Type()&os.ModeSymlink == os.ModeSymlink:
			err := os.MkdirAll(filepath.Dir(path), 0755)
			suite.Require().NoError(err)
			err = os.Symlink(header.Linkname, path)
			suite.Require().NoError(err)
			if strings.HasSuffix(header.Linkname, agentName) {
				suite.agentPath = path
			}
		default:
			suite.T().Logf("Unable to untar type=%c in file=%s", header.Typeflag, path)
		}
	}
}

func (suite *AgentInstallSuite) copyFleetServer(w io.WriteCloser) {
	suite.T().Helper()
	src, err := os.Open(suite.binaryPath)
	suite.Require().NoError(err)
	_, err = io.Copy(w, src)
	suite.Require().NoError(err)
	err = w.Close()
	suite.Require().NoError(err)
	err = src.Close()
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

	out, err := exec.Command("sudo", "elastic-agent", "uninstall", "--force").CombinedOutput()
	suite.Assert().NoErrorf(err, "elastic-agent uninstall failed. Output: %s", out)
}

func (suite *AgentInstallSuite) TestHTTP() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*3)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sudo", suite.agentPath, "install",
		"--fleet-server-es=http://"+suite.ESHosts,
		"--fleet-server-service-token="+suite.ServiceToken,
		"--fleet-server-insecure-http=true",
		"--fleet-server-host=0.0.0.0",
		"--fleet-server-policy=fleet-server-policy",
		"--non-interactive")
	cmd.Env = []string{"GOCOVERDIR=" + suite.CoverPath} // TODO Check if this env var will be passed by the agent to fleet-server
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
		"--url=https://localhost:8220",
		"--certificate-authorities="+filepath.Join(suite.CertPath, "e2e-test-ca.crt"),
		"--fleet-server-es=http://"+suite.ESHosts,
		"--fleet-server-service-token-path="+filepath.Join(dir, "service-token"),
		"--fleet-server-policy=fleet-server-policy",
		"--fleet-server-cert="+filepath.Join(suite.CertPath, "fleet-server.crt"),
		"--fleet-server-cert-key="+filepath.Join(suite.CertPath, "fleet-server.key"),
		"--fleet-server-cert-key-passphrase="+filepath.Join(suite.CertPath, "passphrase"),
		"--non-interactive")
	cmd.Env = []string{"GOCOVERDIR=" + suite.CoverPath} // TODO Check if this env var will be passed by the agent to fleet-server
	cmd.Dir = filepath.Dir(suite.agentPath)

	output, err := cmd.CombinedOutput()
	suite.Require().NoErrorf(err, "elastic-agent install failed. command: %s, exit_code: %d, output: %s", cmd.String(), cmd.ProcessState.ExitCode(), string(output))

	suite.FleetServerStatusOK(ctx, "https://localhost:8220")
}

// testAPMInstrumentationFile tests passing agentt.monitoring.apm.* config options through the elastic-agent.yml file during install time
// it currently does not work, not sure if that is intended behaviour
func (suite *AgentInstallSuite) testAPMInstrumentationFile() {
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
		"TestName": "AgentInstallAPMInstrumentationFile",
	})
	f.Close()
	suite.Require().NoError(err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sudo", suite.agentPath, "install",
		"--fleet-server-es=http://"+suite.ESHosts,
		"--fleet-server-service-token="+suite.ServiceToken,
		"--fleet-server-insecure-http=true",
		"--fleet-server-host=0.0.0.0",
		"--fleet-server-policy=fleet-server-policy",
		"--non-interactive")
	cmd.Env = []string{"GOCOVERDIR=" + suite.CoverPath} // TODO Check if this env var will be passed by the agent to fleet-server
	cmd.Dir = filepath.Dir(suite.agentPath)

	output, err := cmd.CombinedOutput()
	suite.Require().NoErrorf(err, "elastic-agent install failed. command: %s, exit_code: %d, output: %s", cmd.String(), cmd.ProcessState.ExitCode(), string(output))

	suite.FleetServerStatusOK(ctx, "http://localhost:8220")
	suite.HasTestStatusTrace(ctx, "AgentInstallAPMInstrumentationFile")
}

func (suite *AgentInstallSuite) TestAPMInstrumentationPolicy() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
	defer cancel()

	suite.AddPolicyOverrides(ctx, "fleet-server-apm", map[string]interface{}{
		// NOTE: if the following key is specified as agent.monitoring the kibana ui will not merge it correctly in the policy.
		"agent": map[string]interface{}{
			"monitoring": map[string]interface{}{
				"traces": true,
				"apm": map[string]interface{}{
					"hosts":        []interface{}{"http://localhost:8200"},
					"environment":  "test-AgentInstallAPMInstrumentationPolicy",
					"secret_token": "b!gS3cret",
					"global_labels": map[string]interface{}{
						"testName": "AgentInstallAPMInstrumentationPolicy",
					},
				},
			},
		},
	})

	cmd := exec.CommandContext(ctx, "sudo", suite.agentPath, "install",
		"--fleet-server-es=http://"+suite.ESHosts,
		"--fleet-server-service-token="+suite.ServiceToken,
		"--fleet-server-insecure-http=true",
		"--fleet-server-host=0.0.0.0",
		"--fleet-server-policy=fleet-server-apm",
		"--non-interactive")
	cmd.Env = []string{"GOCOVERDIR=" + suite.CoverPath} // TODO Check if this env var will be passed by the agent to fleet-server
	cmd.Dir = filepath.Dir(suite.agentPath)

	output, err := cmd.CombinedOutput()
	suite.Require().NoErrorf(err, "elastic-agent install failed. command: %s, exit_code: %d, output: %s", cmd.String(), cmd.ProcessState.ExitCode(), string(output))

	suite.FleetServerStatusOK(ctx, "http://localhost:8220")
	suite.HasTestStatusTrace(ctx, "AgentInstallAPMInstrumentationPolicy")
}
