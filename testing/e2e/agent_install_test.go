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
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/elastic/fleet-server/v7/version"

	"github.com/stretchr/testify/suite"
)

type AgentInstallSuite struct {
	BaseE2ETestSuite

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
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	}
	// check if agent is installed
	if _, err := exec.LookPath(agentName); err == nil {
		suite.installDetected = true
		return // don't bother with setup, skip all tests
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
}

// downloadAgent will search the artifacts repo for the latest snapshot and return the stream to the download for the current OS + ARCH.
func (suite *AgentInstallSuite) downloadAgent(ctx context.Context) io.ReadCloser {
	suite.T().Helper()
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://artifacts-api.elastic.co/v1/search/%s-SNAPSHOT", version.DefaultVersion), nil)
	suite.Require().NoError(err)

	resp, err := suite.client.Do(req)
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

	fileName := fmt.Sprintf("elastic-agent-%s-SNAPSHOT-%s-%s.%s", version.DefaultVersion, runtime.GOOS, arch, fType)
	pkg, ok := body.Packages[fileName]
	suite.Require().True(ok, "unable to find package download")

	req, err = http.NewRequestWithContext(ctx, "GET", pkg.URL, nil)
	suite.Require().NoError(err)
	resp, err = suite.client.Do(req)
	suite.Require().NoError(err)
	return resp.Body
}

// extractZip treats the passed Reader as a zip stream and unarchives it to a temp dir
// fleet-server binary in archive is replaced by a locally compiled version
// FIXME this method might be broken as it hasn't been tested.
func (suite *AgentInstallSuite) extractZip(r io.Reader) {
	suite.T().Helper()
	// Extract zip stream
	var b bytes.Buffer
	n, err := io.Copy(&b, r)
	suite.Require().NoError(err)
	zipReader, err := zip.NewReader(bytes.NewReader(b.Bytes()), n)
	suite.Require().NoError(err)
	fleetPath := ""
	for _, file := range zipReader.File {
		if file.FileInfo().IsDir() {
			err := os.Mkdir(filepath.Join(suite.downloadPath, file.Name), 0755)
			suite.Require().NoError(err)
		} else {
			dst, err := os.Create(filepath.Join(suite.downloadPath, file.Name))
			suite.Require().NoError(err)
			err = dst.Chmod(file.FileInfo().Mode())
			suite.Require().NoError(err)
			src, err := file.Open()
			suite.Require().NoError(err)
			_, err = io.Copy(dst, src)
			dst.Close() // might be a dirty close
			suite.Require().NoError(err)

			if strings.HasSuffix(file.Name, binaryName) {
				fleetPath = filepath.Join(suite.downloadPath, file.Name)
			}
			if strings.HasSuffix(file.Name, agentName) {
				suite.agentPath = filepath.Join(suite.downloadPath, file.Name)
			}
		}
	}
	suite.Require().NotEmpty(fleetPath, "no fleet-server component detected")
	err = os.Remove(fleetPath)
	suite.Require().NoError(err)
	err = os.Link(suite.binaryPath, fleetPath)
	suite.Require().NoError(err)
}

// extractTar treats the passed Reader as a tar.gz stream and unarchives it to a temp dir
// fleet-server binary in archive is replaced by a locally compiled version
// Additionally the elastic-agent symlink will be recreated.
func (suite *AgentInstallSuite) extractTar(r io.Reader) {
	suite.T().Helper()
	var fleetPath, agentSrc, agentDst, agentLink string
	// Extract tar.gz stream
	stream, err := gzip.NewReader(r)
	suite.Require().NoError(err)
	tarReader := tar.NewReader(stream)
	for header, err := tarReader.Next(); err == nil; header, err = tarReader.Next() {
		if header.FileInfo().IsDir() {
			// headers may be specified out of order in the archive, as a shortcut we'll make all nested dirs
			err := os.MkdirAll(filepath.Join(suite.downloadPath, header.Name), 0755)
			suite.Require().NoError(err)
			continue
		}
		if !header.FileInfo().Mode().IsRegular() {
			// the elastic-agent may count as a symlink in Linux or MacOS bundles
			if header.FileInfo().Name() == agentName {
				agentDst = filepath.Join(suite.downloadPath, header.Name)
				agentLink = header.Linkname
				continue
			}
			suite.T().Logf("unable to extract irregular file: %s linkname: %s", header.Name, header.Linkname)
			continue
		}

		var pathErr *os.PathError
		dst, err := os.Create(filepath.Join(suite.downloadPath, header.Name))
		// if we get a PathError, try to make the directory before retrying file creation
		// headers may be specified out of order in the archive, as a shortcut we'll make all nested dirs
		if errors.As(err, &pathErr) {
			dir := filepath.Dir(header.Name)
			err = os.MkdirAll(filepath.Join(suite.downloadPath, dir), 0755)
			suite.Require().NoErrorf(err, "unable to create directory %s", dir)
			dst, err = os.Create(filepath.Join(suite.downloadPath, header.Name))
			suite.Require().NoErrorf(err, "unable to create file %s", header.Name)
		} else if err != nil {
			suite.Require().Failf("unable to create file", "filename: %s, error: %v", header.Name, err)
		}
		err = dst.Chmod(header.FileInfo().Mode())
		suite.Require().NoError(err)
		_, err = io.Copy(dst, tarReader)
		dst.Close() // might be a dirty close
		suite.Require().NoError(err)

		// note the fleet-server locaction in the extracted path
		if strings.HasSuffix(header.Name, binaryName) {
			fleetPath = filepath.Join(suite.downloadPath, header.Name)
		}
		// note if elastic-agent has been extracted as a regular file
		if strings.HasSuffix(header.Name, agentName) {
			suite.agentPath = filepath.Join(suite.downloadPath, header.Name)
		}
		// note the source of the elastic-agent if it has been detected as a symlink
		if strings.HasSuffix(header.Name, agentLink) {
			agentSrc = filepath.Join(suite.downloadPath, header.Name)
		}
	}
	// Copy fleet-server binary to un archived package
	suite.Require().NotEmpty(fleetPath, "no fleet-server component detected")
	err = os.Remove(fleetPath)
	suite.Require().NoError(err)
	err = os.Link(suite.binaryPath, fleetPath)
	suite.Require().NoError(err)

	// link elastic-agent to the actual binary
	if agentLink != "" {
		suite.Require().NotEmpty(agentSrc, "agent link src undetected")
		suite.Require().NotEmpty(agentDst, "agent link dst undetected")
		err = os.Symlink(agentSrc, agentDst)
		suite.Require().NoError(err)
		suite.agentPath = agentDst // replace path if we are using a link
	}
}

func (suite *AgentInstallSuite) TearDownSuite() {
	if suite.downloadPath != "" {
		err := os.RemoveAll(suite.downloadPath)
		suite.Require().NoErrorf(err, "failed to remove download from %s", suite.downloadPath)
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
	path, err := exec.LookPath(agentName)
	if err != nil {
		suite.T().Logf("unable to detect elastic-agent install on test tear-down: %s", err)
		return
	}
	err = exec.Command(path, "uninstall", "--force").Run()
	suite.Require().NoError(err, "elastic-agent uninstall failed.")
}

func (suite *AgentInstallSuite) TestHTTP() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*3)
	defer cancel()

	cmd := exec.CommandContext(ctx, suite.agentPath, "install",
		"--fleet-server-es="+suite.esHosts,
		"--fleet-server-service-token="+suite.serviceToken,
		"--fleet-server-insecure-http=true",
		"--fleet-server-host=0.0.0.0",
		"--fleet-server-policy=fleet-server-policy",
		"--non-interactive")
	cmd.Env = []string{"GOCOVERDIR=" + suite.coverPath} // TODO Check if this env var will be passed by the agent to fleet-server
	cmd.Dir = filepath.Dir(suite.agentPath)

	output, err := cmd.CombinedOutput()
	suite.Require().NoErrorf(err, "elastic-agent install failed. command: %s, exit_code: %d, output: %s", cmd.String(), cmd.ProcessState.ExitCode(), string(output))

	suite.FleetServerStatusOK(ctx, "http://localhost:8220")
}

func (suite *AgentInstallSuite) TestWithSecretFiles() {
	dir := suite.T().TempDir()
	err := os.WriteFile(filepath.Join(dir, "service-token"), []byte(suite.serviceToken), 0600)
	suite.Require().NoError(err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*3)
	defer cancel()

	cmd := exec.CommandContext(ctx, suite.agentPath, "install",
		"--url=https://localhost:8200",
		"--certificate-authorities="+filepath.Join(suite.certPath, "e2e-test-ca.crt"),
		"--fleet-server-es="+suite.esHosts,
		"--fleet-server-service-token-path="+filepath.Join(dir, "service-token"),
		"--fleet-server-policy=fleet-server-policy",
		"--fleet-server-cert="+filepath.Join(suite.certPath, "fleet-server.crt"),
		"--fleet-server-cert-key="+filepath.Join(suite.certPath, "fleet-server.key"),
		"--fleet-server-cert-key-passphrase="+filepath.Join(suite.certPath, "passphrase"),
		"--non-interactive")
	cmd.Env = []string{"GOCOVERDIR=" + suite.coverPath} // TODO Check if this env var will be passed by the agent to fleet-server
	cmd.Dir = filepath.Dir(suite.agentPath)

	output, err := cmd.CombinedOutput()
	suite.Require().NoErrorf(err, "elastic-agent install failed. command: %s, exit_code: %d, output: %s", cmd.String(), cmd.ProcessState.ExitCode(), string(output))

	suite.FleetServerStatusOK(ctx, "https://localhost:8220")
}
