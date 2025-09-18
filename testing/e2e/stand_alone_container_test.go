// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build e2e && !requirefips

package e2e

import (
	"context"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/elastic/fleet-server/testing/e2e/scaffold"

	toxiproxy "github.com/Shopify/toxiproxy/v2/client"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
)

const fleetPort = "8220/tcp"

type StandAloneContainerSuite struct {
	scaffold.Scaffold

	container testcontainers.Container

	dockerImg string
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

	v, ok := os.LookupEnv("STANDALONE_E2E_IMAGE")
	suite.Require().True(ok, "expected STANDALONE_E2E_IMAGE to be defined")
	suite.dockerImg = v

	// Run the fleet server container.
	req := testcontainers.ContainerRequest{
		Hostname:     "fleet-server",
		Image:        suite.dockerImg,
		ExposedPorts: []string{fleetPort},
		Networks:     []string{"integration_default"},
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
			"ServiceToken": suite.ServiceToken,
		},
	})

	endpoint, err := suite.container.PortEndpoint(ctx, fleetPort, "http")
	suite.Require().NoError(err)

	suite.FleetServerStatusOK(ctx, endpoint)
}

// TestWithElasticsearchConnectionFailures checks the behaviour of stand alone Fleet Server
// when Elasticsearch is not reachable.
func (suite *StandAloneContainerSuite) TestWithElasticsearchConnectionFailures() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	proxyContainer := suite.StartToxiproxy(ctx)
	proxyEndpoint, err := proxyContainer.URI(ctx)
	suite.Require().NoError(err)
	proxyClient := toxiproxy.NewClient(proxyEndpoint)

	suite.startFleetServer(ctx, standaloneContainerOptions{
		Template: "stand-alone-http.tpl",
		TemplateData: map[string]string{
			"Hosts":        "http://toxi:8666", // Toxiproxy ports start at 8666, fleet-server starts in the integration test network and can use the port directly.
			"ServiceToken": suite.ServiceToken,
		},
	})

	endpoint, err := suite.container.PortEndpoint(ctx, fleetPort, "http")
	suite.Require().NoError(err)

	// Wait to check that it is healthy.
	suite.FleetServerStatusIs(ctx, endpoint, client.UnitStateHealthy)

	proxy, err := proxyClient.Proxy("es")
	suite.Require().NoError(err)

	// Provoke timeouts and wait for the healthcheck to fail.
	_, err = proxy.AddToxic("force_timeout", "timeout", "upstream", 1.0, toxiproxy.Attributes{})
	suite.Require().NoError(err)
	suite.FleetServerStatusIs(ctx, endpoint, client.UnitStateDegraded)

	// Recover the network and wait for the healthcheck to be healthy again.
	err = proxy.RemoveToxic("force_timeout")
	suite.Require().NoError(err)
	suite.FleetServerStatusIs(ctx, endpoint, client.UnitStateHealthy)
}

func (suite *StandAloneContainerSuite) TestAPMInstrumentation() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*3)
	defer cancel()

	suite.startFleetServer(ctx, standaloneContainerOptions{
		Template: "stand-alone-apm.tpl",
		TemplateData: map[string]string{
			"Hosts":        "http://elasticsearch:9200",
			"ServiceToken": suite.ServiceToken,
			"APMHost":      "http://apm-server:8200",
			"TestName":     "StandAloneContainerAPMInstrumentation",
		},
	})

	endpoint, err := suite.container.PortEndpoint(ctx, fleetPort, "http")
	suite.Require().NoError(err)

	suite.FleetServerStatusOK(ctx, endpoint)
	suite.HasTestStatusTrace(ctx, "StandAloneContainerAPMInstrumentation", nil)
}
