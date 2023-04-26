// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build e2e

package e2e

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type AgentContainerSuite struct {
	BaseE2ETestSuite

	dockerCmd string
	dockerImg string
}

func TestAgentContainerSuite(t *testing.T) {
	suite.Run(t, new(AgentContainerSuite))
}

func (suite *AgentContainerSuite) SetupSuite() {
	path, err := exec.LookPath("docker")
	suite.Require().NoError(err)
	suite.dockerCmd = path

	v, ok := os.LookupEnv("AGENT_E2E_IMAGE")
	suite.Require().True(ok, "expected AGENT_E2E_IMAGE to be defined")
	suite.dockerImg = v

	// Sanity check docker
	cmd := exec.Command(suite.dockerCmd, "image", "inspect", suite.dockerImg)
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
	// stop the container when test ends
	err := exec.Command(suite.dockerCmd, "stop", "fleet-server").Run()
	suite.Require().NoError(err)
}

func (suite *AgentContainerSuite) TestHTTP() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, suite.dockerCmd, "run", "--rm",
		"--name", "fleet-server",
		"-e", "FLEET_SERVER_ENABLE=1",
		"-e", "FLEET_SERVER_ELASTICSEARCH_HOST=http://elasticsearch:9200",
		"-e", "FLEET_SERVER_SERVICE_TOKEN="+suite.serviceToken,
		"-e", "FLEET_SERVER_POLICY_ID=fleet-server-policy",
		"-e", "FLEET_SERVER_INSECURE_HTTP=true",
		"-e", "FLEET_SERVER_HOST=0.0.0.0",
		"-p", "8220:8220",
		"--network", "integration_default",
		suite.dockerImg)

	err := cmd.Start()
	suite.Require().NoError(err)

	suite.FleetServerStatusOK(ctx, "http://localhost:8220")
	cancel()
	cmd.Wait()
}

func (suite *AgentContainerSuite) TestWithSecretFiles() {
	// Create a service token file in the temp test dir
	dir := suite.T().TempDir()
	err := os.WriteFile(filepath.Join(dir, "service-token"), []byte(suite.serviceToken), 0600)
	suite.Require().NoError(err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, suite.dockerCmd, "run", "--rm",
		"--name", "fleet-server",
		"-v", suite.certPath+":/certs:ro",
		"-v", dir+":/token:ro",
		"-e", "FLEET_SERVER_ENABLE=1",
		"-e", "FLEET_SERVER_CERT=/certs/fleet-server.crt",
		"-e", "FLEET_SERVER_CERT_KEY=/certs/fleet-server.key",
		"-e", "FLEET_SERVER_CERT_KEY_PASSPHRASE=/certs/passphrase",
		"-e", "FLEET_SERVER_SERVICE_TOKEN_PATH=/token/service-token",
		"-e", "FLEET_SERVER_ELASTICSEARCH_HOST=http://elasticsearch:9200",
		"-e", "FLEET_SERVER_POLICY_ID=fleet-server-policy",
		"-p", "8220:8220",
		"--network", "integration_default",
		suite.dockerImg)

	err = cmd.Start()
	suite.Require().NoError(err)

	suite.FleetServerStatusOK(ctx, "https://localhost:8220")
	cancel()
	cmd.Wait()
}
