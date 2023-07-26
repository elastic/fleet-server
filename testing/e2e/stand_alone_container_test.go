// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	toxiproxy "github.com/Shopify/toxiproxy/client"
	"github.com/docker/docker/api/types/container"
	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"

	"github.com/elastic/fleet-server/v7/version"
)

type StandAloneContainerSuite struct {
	BaseE2ETestSuite

	container testcontainers.Container
}

func TestStandAloneContainerSuite(t *testing.T) {
	suite.Run(t, new(StandAloneContainerSuite))
}

func (suite *StandAloneContainerSuite) SetupSuite() {
	suite.Setup() // base setup
}

func (suite *StandAloneContainerSuite) SetupTest() {
	portFree := suite.IsFleetServerPortFree()
	suite.Require().True(portFree, "port 8220 must not be in use for test to start")
}

func (suite *StandAloneContainerSuite) TearDownTest() {
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
	suite.DeleteAllAgents(context.Background())
}

type standaloneContainerOptions struct {
	Template     string
	TemplateData map[string]string
	NetworkMode  string
}

func (suite *StandAloneContainerSuite) startFleetServer(ctx context.Context, options standaloneContainerOptions) {
	rootDir := filepath.Join("..", "..")
	d, err := os.ReadFile(filepath.Join(rootDir, ".go-version"))
	suite.Require().NoError(err)
	goVersion := strings.TrimSpace(string(d))
	serverVersion := version.DefaultVersion

	// Create a config file from a template in the test temp dir
	dir := suite.T().TempDir()
	tpl, err := template.ParseFiles(filepath.Join("testdata", options.Template))
	suite.Require().NoError(err)
	configPath := filepath.Join(dir, "config.yml")
	f, err := os.Create(configPath)
	suite.Require().NoError(err)
	err = tpl.Execute(f, options.TemplateData)
	f.Close()
	suite.Require().NoError(err)

	networks := []string{"integration_default"}
	networkMode := container.NetworkMode(options.NetworkMode)
	if networkMode == "host" {
		networks = nil
	}

	targetOs := "linux"
	targetArch := runtime.GOARCH
	targetPlatform := fmt.Sprintf("%s/%s", targetOs, targetArch)

	// Run the fleet server container.
	req := testcontainers.ContainerRequest{
		Hostname: "fleet-server",
		FromDockerfile: testcontainers.FromDockerfile{
			Context: rootDir,
			BuildArgs: map[string]*string{
				"GO_VERSION":     &goVersion,
				"VERSION":        &serverVersion,
				"BUILDPLATFORM":  &targetPlatform,
				"TARGETOS":       &targetOs,
				"TARGETARCH":     &targetArch,
				"TARGETPLATFORM": &targetPlatform,
			},
			PrintBuildLog: true,
		},
		ExposedPorts: []string{"8220/tcp"},
		Networks:     networks,
		NetworkMode:  networkMode,
		Mounts: testcontainers.ContainerMounts{
			testcontainers.ContainerMount{
				Source: &testcontainers.GenericBindMountSource{configPath},
				Target: "/etc/fleet-server.yml",
			},
		},
		WaitingFor: containerWaitForHealthyStatus(),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
		Logger:           &logger{suite.T()},
	})
	suite.Require().NoError(err)
	suite.container = container
}

func (suite *StandAloneContainerSuite) TestHTTP() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	suite.startFleetServer(ctx, standaloneContainerOptions{
		Template: "stand-alone-http.tpl",
		TemplateData: map[string]string{
			"Hosts":        "http://elasticsearch:9200",
			"ServiceToken": suite.serviceToken,
		},
	})

	endpoint, err := suite.container.PortEndpoint(ctx, "8220/tcp", "http")
	suite.Require().NoError(err)

	suite.FleetServerStatusOK(ctx, endpoint)
}

// TestWithElasticsearchConnectionFailures checks the behaviour of stand alone Fleet Server
// when Elasticsearch is not reachable.
func (suite *StandAloneContainerSuite) TestWithElasticsearchConnectionFailures() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	proxy, err := suite.StartToxiproxy(ctx).CreateProxy("es", "localhost:0", suite.esHosts)
	suite.Require().NoError(err)

	suite.startFleetServer(ctx, standaloneContainerOptions{
		Template:    "stand-alone-http.tpl",
		NetworkMode: "host",
		TemplateData: map[string]string{
			"Hosts":        "http://" + proxy.Listen,
			"ServiceToken": suite.serviceToken,
		},
	})

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
}
