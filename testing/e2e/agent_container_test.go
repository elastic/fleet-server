// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build e2e

package e2e

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
)

type logger struct {
	*testing.T
}

func (l *logger) Printf(format string, v ...interface{}) {
	l.Helper()
	l.Logf(format, v...)
}

type AgentContainerSuite struct {
	BaseE2ETestSuite

	dockerImg string

	container testcontainers.Container
}

func TestAgentContainerSuite(t *testing.T) {
	suite.Run(t, new(AgentContainerSuite))
}

func (suite *AgentContainerSuite) SetupSuite() {
	path, err := exec.LookPath("docker")
	suite.Require().NoError(err)

	v, ok := os.LookupEnv("AGENT_E2E_IMAGE")
	suite.Require().True(ok, "expected AGENT_E2E_IMAGE to be defined")
	suite.dockerImg = v

	// Sanity check docker
	cmd := exec.Command(path, "image", "inspect", suite.dockerImg)
	output, err := cmd.CombinedOutput()
	suite.Require().NoError(err, "unable to run docker, output: ", string(output))

	suite.Setup()
	suite.SetupKibana()
}

func (suite *AgentContainerSuite) SetupTest() {
	portFree := suite.IsFleetServerPortFree()
	suite.Require().True(portFree, "port 8220 must not be in use for test to start")
}

func (suite *AgentContainerSuite) TearDownTest() {
	if suite.container == nil {
		return
	}
	// stop the container when test ends
	if suite.T().Failed() {
		rc, err := suite.container.Logs(context.Background())
		if err != nil {
			suite.T().Logf("unable to get container logs: %v", err)
		} else {
			p, err := io.ReadAll(rc)
			suite.T().Logf("failed test log read err: %v, container logs:\n%s", err, string(p))
			rc.Close()
		}
	}
	err := suite.container.Terminate(context.Background())
	suite.Require().NoError(err)
	suite.container = nil
}

func (suite *AgentContainerSuite) TestHTTP() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	req := testcontainers.ContainerRequest{
		Image: suite.dockerImg,
		Env: map[string]string{
			"GOCOVERDIR":                      "/cover",
			"FLEET_SERVER_ENABLE":             "1",
			"FLEET_SERVER_POLICY_ID":          "fleet-server-policy",
			"FLEET_SERVER_ELASTICSEARCH_HOST": "http://elasticsearch:9200",
			"FLEET_SERVER_SERVICE_TOKEN":      suite.serviceToken,
			"FLEET_SERVER_INSECURE_HTTP":      "true",
			"FLEET_SERVER_HOST":               "0.0.0.0",
		},
		ExposedPorts: []string{"8220/tcp"},
		Networks:     []string{"integration_default"},
		Mounts: testcontainers.ContainerMounts{
			testcontainers.ContainerMount{
				Source: &testcontainers.GenericBindMountSource{suite.coverPath},
				Target: "/cover",
			},
		},
	}
	fleetC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
		Logger:           &logger{suite.T()},
	})
	suite.Require().NoError(err)
	suite.container = fleetC

	endpoint, err := fleetC.Endpoint(ctx, "http")
	suite.Require().NoError(err)

	suite.FleetServerStatusOK(ctx, endpoint)
}

func (suite *AgentContainerSuite) TestWithSecretFiles() {
	// Create a service token file in the temp test dir
	dir := suite.T().TempDir()
	err := os.WriteFile(filepath.Join(dir, "service-token"), []byte(suite.serviceToken), 0644)
	suite.Require().NoError(err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	req := testcontainers.ContainerRequest{
		Image: suite.dockerImg,
		Env: map[string]string{
			"GOCOVERDIR":                       "/cover",
			"FLEET_SERVER_ENABLE":              "1",
			"FLEET_URL":                        "https://fleet-server:8200",
			"FLEET_CA":                         "/tmp/e2e-test-ca.crt",
			"FLEET_SERVER_CERT":                "/tmp/fleet-server.crt",
			"FLEET_SERVER_CERT_KEY":            "/tmp/fleet-server.key",
			"FLEET_SERVER_CERT_KEY_PASSPHRASE": "/tmp/passphrase",
			"FLEET_SERVER_SERVICE_TOKEN_PATH":  "/token/service-token",
			"FLEET_SERVER_ELASTICSEARCH_HOST":  "http://elasticsearch:9200",
			"FLEET_SERVER_POLICY_ID":           "fleet-server-policy",
		},
		ExposedPorts: []string{"8220/tcp"},
		Networks:     []string{"integration_default"},
		// certs are copied so they can be readable by fleet-server.
		Files: []testcontainers.ContainerFile{{
			HostFilePath:      filepath.Join(suite.certPath, "e2e-test-ca.crt"),
			ContainerFilePath: "/tmp/e2e-test-ca.crt",
			FileMode:          644,
		}, {
			HostFilePath:      filepath.Join(suite.certPath, "fleet-server.crt"),
			ContainerFilePath: "/tmp/fleet-server.crt",
			FileMode:          644,
		}, {
			HostFilePath:      filepath.Join(suite.certPath, "fleet-server.key"),
			ContainerFilePath: "/tmp/fleet-server.key",
			FileMode:          644,
		}, {
			HostFilePath:      filepath.Join(suite.certPath, "passphrase"),
			ContainerFilePath: "/tmp/passphrase",
			FileMode:          644,
		}},
		Mounts: testcontainers.ContainerMounts{
			testcontainers.ContainerMount{
				Source:   &testcontainers.GenericBindMountSource{dir},
				Target:   "/token",
				ReadOnly: true,
			},
			testcontainers.ContainerMount{
				Source: &testcontainers.GenericBindMountSource{suite.coverPath},
				Target: "/cover",
			},
		},
	}
	fleetC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
		Logger:           &logger{suite.T()},
	})
	suite.Require().NoError(err)
	suite.container = fleetC

	endpoint, err := fleetC.Endpoint(ctx, "https")
	suite.Require().NoError(err)

	suite.FleetServerStatusOK(ctx, endpoint)
}
