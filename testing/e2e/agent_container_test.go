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
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/elastic/fleet-server/testing/e2e/scaffold"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
)

// NOTE: GOCOVERDIR is specied when manipulating the container, but is not defined in the fleet-server spec and is not passed to fleet-server

type AgentContainerSuite struct {
	scaffold.Scaffold

	dockerImg string

	container testcontainers.Container
	agentID   string
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
	suite.DeleteAllAgents(context.Background())
	suite.agentID = ""
}

// FleetIsHealthy ensures that the agent managing fleet-server is online.
//
// It checks the status API on the fleet-server's external port and that the agent listed in Kibana states "online"
// Tests that enroll another agent explicitly need fleet-server to be online
func (suite *AgentContainerSuite) FleetIsHealthy(bCtx context.Context, endpoint string) {
	ctx, cancel := context.WithTimeout(bCtx, time.Minute)
	defer cancel()
	suite.FleetServerStatusOK(ctx, endpoint)

	if suite.agentID != "" {
		suite.AgentIsOnline(ctx, suite.agentID)
		return
	}

	suite.agentID = suite.NewFleetIsOnline(ctx)
}

func (suite *AgentContainerSuite) TestHTTP() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	req := testcontainers.ContainerRequest{
		Hostname: "fleet-server",
		Image:    suite.dockerImg,
		Env: map[string]string{
			"GOCOVERDIR":                      "/cover",
			"FLEET_SERVER_ENABLE":             "1",
			"FLEET_SERVER_POLICY_ID":          "fleet-server-policy",
			"FLEET_SERVER_ELASTICSEARCH_HOST": "http://elasticsearch:9200",
			"FLEET_SERVER_SERVICE_TOKEN":      suite.ServiceToken,
			"FLEET_SERVER_INSECURE_HTTP":      "true",
			"FLEET_SERVER_HOST":               "0.0.0.0",
		},
		ExposedPorts: []string{"8220/tcp"},
		Networks:     []string{"integration_default"},
		HostConfigModifier: func(cfg *container.HostConfig) {
			if cfg.Mounts == nil {
				cfg.Mounts = make([]mount.Mount, 0)
			}
			cfg.Mounts = append(cfg.Mounts, mount.Mount{
				Type:   mount.TypeBind,
				Source: suite.CoverPath,
				Target: "/cover",
			})
		},
		WaitingFor: containerWaitForHealthyStatus(),
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

	suite.FleetIsHealthy(ctx, endpoint)
}

func (suite *AgentContainerSuite) TestWithSecretFiles() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	req := testcontainers.ContainerRequest{
		Hostname: "fleet-server",
		Image:    suite.dockerImg,
		Env: map[string]string{
			"GOCOVERDIR":                       "/cover",
			"FLEET_SERVER_ENABLE":              "1",
			"FLEET_URL":                        "https://fleet-server:8220",
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
			HostFilePath:      filepath.Join(suite.CertPath, "e2e-test-ca.crt"),
			ContainerFilePath: "/tmp/e2e-test-ca.crt",
			FileMode:          0644,
		}, {
			HostFilePath:      filepath.Join(suite.CertPath, "fleet-server.crt"),
			ContainerFilePath: "/tmp/fleet-server.crt",
			FileMode:          0644,
		}, {
			HostFilePath:      filepath.Join(suite.CertPath, "fleet-server.key"),
			ContainerFilePath: "/tmp/fleet-server.key",
			FileMode:          0644,
		}, {
			HostFilePath:      filepath.Join(suite.CertPath, "passphrase"),
			ContainerFilePath: "/tmp/passphrase",
			FileMode:          0644,
		}, {
			Reader:            strings.NewReader(suite.ServiceToken),
			ContainerFilePath: "/token/service-token",
			FileMode:          0644,
		}},
		HostConfigModifier: func(cfg *container.HostConfig) {
			if cfg.Mounts == nil {
				cfg.Mounts = make([]mount.Mount, 0)
			}
			cfg.Mounts = append(cfg.Mounts, mount.Mount{
				Type:   mount.TypeBind,
				Source: suite.CoverPath,
				Target: "/cover",
			})
		},
		WaitingFor: containerWaitForHealthyStatus().WithTLS(true, nil),
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

	suite.FleetIsHealthy(ctx, endpoint)
}

// TestSleep10m checks if the fleet-server is healthy after 10m
// skipped unless the "-long" flag is provided.
func (suite *AgentContainerSuite) TestSleep10m() {
	if !longFlag {
		suite.T().Skip("Long tests skipped. Enable with -long.")
	}
	bCtx, bCancel := context.WithCancel(context.Background())
	defer bCancel()

	req := testcontainers.ContainerRequest{
		Hostname: "fleet-server",
		Image:    suite.dockerImg,
		Env: map[string]string{
			"GOCOVERDIR":                       "/cover",
			"FLEET_SERVER_ENABLE":              "1",
			"FLEET_URL":                        "https://fleet-server:8220",
			"FLEET_CA":                         "/tmp/e2e-test-ca.crt",
			"FLEET_SERVER_CERT":                "/tmp/fleet-server.crt",
			"FLEET_SERVER_CERT_KEY":            "/tmp/fleet-server.key",
			"FLEET_SERVER_CERT_KEY_PASSPHRASE": "/tmp/passphrase",
			"FLEET_SERVER_SERVICE_TOKEN":       suite.ServiceToken,
			"FLEET_SERVER_ELASTICSEARCH_HOST":  "http://elasticsearch:9200",
			"FLEET_SERVER_POLICY_ID":           "fleet-server-policy",
		},
		ExposedPorts: []string{"8220/tcp"},
		Networks:     []string{"integration_default"},
		// certs are copied so they can be readable by fleet-server.
		Files: []testcontainers.ContainerFile{{
			HostFilePath:      filepath.Join(suite.CertPath, "e2e-test-ca.crt"),
			ContainerFilePath: "/tmp/e2e-test-ca.crt",
			FileMode:          0644,
		}, {
			HostFilePath:      filepath.Join(suite.CertPath, "fleet-server.crt"),
			ContainerFilePath: "/tmp/fleet-server.crt",
			FileMode:          0644,
		}, {
			HostFilePath:      filepath.Join(suite.CertPath, "fleet-server.key"),
			ContainerFilePath: "/tmp/fleet-server.key",
			FileMode:          0644,
		}, {
			HostFilePath:      filepath.Join(suite.CertPath, "passphrase"),
			ContainerFilePath: "/tmp/passphrase",
			FileMode:          0644,
		}},
		HostConfigModifier: func(cfg *container.HostConfig) {
			if cfg.Mounts == nil {
				cfg.Mounts = make([]mount.Mount, 0)
			}
			cfg.Mounts = append(cfg.Mounts, mount.Mount{
				Type:   mount.TypeBind,
				Source: suite.CoverPath,
				Target: "/cover",
			})
		},
		WaitingFor: containerWaitForHealthyStatus().WithTLS(true, nil),
	}
	fleetC, err := testcontainers.GenericContainer(bCtx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
		Logger:           &logger{suite.T()},
	})
	suite.Require().NoError(err)
	suite.container = fleetC

	endpoint, err := fleetC.Endpoint(bCtx, "https")
	suite.Require().NoError(err)

	suite.FleetIsHealthy(bCtx, endpoint)

	suite.T().Log("sleeping for 10m")
	time.Sleep(time.Minute * 10)

	suite.FleetIsHealthy(bCtx, endpoint)
}

// TestDockerAgent will enroll a real agent running in a docker container.
// It uses the dummy-policy (no monitoring or integrations).
// The test is successful if it reaches the "online" state in Kibana within 5 minutes of the container starting.
//
// NOTE: This is intended as a sanity check. Additional fleet-server/elastic-agent are not tested.
func (suite *AgentContainerSuite) TestDockerAgent() {
	bCtx, bCancel := context.WithCancel(context.Background())
	defer bCancel()

	req := testcontainers.ContainerRequest{
		Hostname: "fleet-server",
		Image:    suite.dockerImg,
		Env: map[string]string{
			"GOCOVERDIR":                       "/cover",
			"FLEET_SERVER_ENABLE":              "1",
			"FLEET_URL":                        "https://fleet-server:8220",
			"FLEET_CA":                         "/tmp/e2e-test-ca.crt",
			"FLEET_SERVER_CERT":                "/tmp/fleet-server.crt",
			"FLEET_SERVER_CERT_KEY":            "/tmp/fleet-server.key",
			"FLEET_SERVER_CERT_KEY_PASSPHRASE": "/tmp/passphrase",
			"FLEET_SERVER_SERVICE_TOKEN":       suite.ServiceToken,
			"FLEET_SERVER_ELASTICSEARCH_HOST":  "http://elasticsearch:9200",
			"FLEET_SERVER_POLICY_ID":           "fleet-server-policy",
		},
		ExposedPorts: []string{"8220/tcp"},
		Networks:     []string{"integration_default"},
		// certs are copied so they can be readable by fleet-server.
		Files: []testcontainers.ContainerFile{{
			HostFilePath:      filepath.Join(suite.CertPath, "e2e-test-ca.crt"),
			ContainerFilePath: "/tmp/e2e-test-ca.crt",
			FileMode:          0644,
		}, {
			HostFilePath:      filepath.Join(suite.CertPath, "fleet-server.crt"),
			ContainerFilePath: "/tmp/fleet-server.crt",
			FileMode:          0644,
		}, {
			HostFilePath:      filepath.Join(suite.CertPath, "fleet-server.key"),
			ContainerFilePath: "/tmp/fleet-server.key",
			FileMode:          0644,
		}, {
			HostFilePath:      filepath.Join(suite.CertPath, "passphrase"),
			ContainerFilePath: "/tmp/passphrase",
			FileMode:          0644,
		}},
		HostConfigModifier: func(cfg *container.HostConfig) {
			if cfg.Mounts == nil {
				cfg.Mounts = make([]mount.Mount, 0)
			}
			cfg.Mounts = append(cfg.Mounts, mount.Mount{
				Type:   mount.TypeBind,
				Source: suite.CoverPath,
				Target: "/cover",
			})
		},
		WaitingFor: containerWaitForHealthyStatus().WithTLS(true, nil),
	}
	fleetC, err := testcontainers.GenericContainer(bCtx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
		Logger:           &logger{suite.T()},
	})
	suite.Require().NoError(err)
	suite.container = fleetC

	endpoint, err := fleetC.Endpoint(bCtx, "https")
	suite.Require().NoError(err)

	suite.FleetIsHealthy(bCtx, endpoint)

	enrollmentKey := suite.GetEnrollmentTokenForPolicyID(bCtx, "dummy-policy")
	req = testcontainers.ContainerRequest{
		Image: suite.dockerImg,
		Env: map[string]string{
			"GOCOVERDIR":             "/cover",
			"FLEET_ENROLL":           "1",
			"FLEET_URL":              "https://fleet-server:8220",
			"FLEET_CA":               "/tmp/e2e-test-ca.crt",
			"FLEET_ENROLLMENT_TOKEN": enrollmentKey,
		},
		Networks: []string{"integration_default"},
		// certs are copied so they can be readable by fleet-server.
		Files: []testcontainers.ContainerFile{{
			HostFilePath:      filepath.Join(suite.CertPath, "e2e-test-ca.crt"),
			ContainerFilePath: "/tmp/e2e-test-ca.crt",
			FileMode:          0644,
		}},
		Mounts: testcontainers.ContainerMounts{
			testcontainers.ContainerMount{
				Source: &testcontainers.GenericBindMountSource{suite.CoverPath},
				Target: "/cover",
			},
		},
	}
	agentC, err := testcontainers.GenericContainer(bCtx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
		Logger:           &logger{suite.T()},
	})
	suite.Require().NoError(err)
	// Read agent logs if the test failed
	// terminate the agent
	defer func() {
		if suite.T().Failed() {
			rc, err := agentC.Logs(bCtx)
			if err != nil {
				suite.T().Logf("elastic-agent container unable to get logs: %v", err)
			} else {
				p, err := io.ReadAll(rc)
				suite.T().Logf("elastic-agent container logs (read err: %v):\n%s", err, string(p))
				rc.Close()
			}

		}
		err := agentC.Terminate(bCtx)
		suite.Require().NoError(err)
	}()

	ctx, cancel := context.WithTimeout(bCtx, time.Minute*5)
	defer cancel()
	timer := time.NewTimer(time.Second)
	agentID := ""

	for {
		select {
		case <-ctx.Done():
			suite.Require().NoError(ctx.Err(), "context expired before agent reported online")
		case <-timer.C:
			// on the 1st iteration of the loop we don't know the agent ID that the container agent uses
			if agentID == "" {
				// getAgents should (eventually) return the fleet-server and the agent
				status, agents := suite.GetAgents(ctx)
				if status != 200 {
					timer.Reset(time.Second)
					continue
				}
				for _, agent := range agents {
					if agent.ID != suite.agentID {
						// found the enrolled agent and it's healthy
						if agent.Status == "online" {
							return
						}
						// found enrolled agent in different state
						agentID = suite.agentID
						continue
					}
				}
				timer.Reset(time.Second)
				continue
			}
			// we know what the enrolled agent id is
			suite.AgentIsOnline(ctx, agentID)
			return
		}
	}
}

func (suite *AgentContainerSuite) TestAPMInstrumentationFile() {
	suite.T().Skip("Testcase requires https://github.com/elastic/fleet-server/issues/3526 to be resolved.")
	dir := suite.T().TempDir()
	tpl, err := template.ParseFiles(filepath.Join("testdata", "agent-install-apm.tpl"))
	suite.Require().NoError(err)
	configPath := filepath.Join(dir, "elastic-agent.yml")
	f, err := os.Create(configPath)
	suite.Require().NoError(err)
	err = tpl.Execute(f, map[string]string{
		"APMHost":  "http://apm-server:8200",
		"TestName": "AgentContainerAPMInstrumentationFile",
	})
	f.Close()
	suite.Require().NoError(err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	req := testcontainers.ContainerRequest{
		Hostname: "fleet-server",
		Image:    suite.dockerImg,
		Env: map[string]string{
			"GOCOVERDIR":                      "/cover",
			"FLEET_SERVER_ENABLE":             "1",
			"FLEET_SERVER_POLICY_ID":          "fleet-server-policy",
			"FLEET_SERVER_ELASTICSEARCH_HOST": "http://elasticsearch:9200",
			"FLEET_SERVER_SERVICE_TOKEN":      suite.ServiceToken,
			"FLEET_SERVER_INSECURE_HTTP":      "true",
			"FLEET_SERVER_HOST":               "0.0.0.0",
		},
		ExposedPorts: []string{"8220/tcp"},
		Networks:     []string{"integration_default"},
		HostConfigModifier: func(cfg *container.HostConfig) {
			if cfg.Mounts == nil {
				cfg.Mounts = make([]mount.Mount, 0)
			}
			cfg.Mounts = append(cfg.Mounts, mount.Mount{
				Type:   mount.TypeBind,
				Source: suite.CoverPath,
				Target: "/cover",
			}, mount.Mount{
				Type:   mount.TypeBind,
				Source: dir,
				Target: "/usr/share/elastic-agent/state",
			})
		},
		WaitingFor: containerWaitForHealthyStatus(),
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

	suite.FleetIsHealthy(ctx, endpoint)
	suite.HasTestStatusTrace(ctx, "AgentContainerAPMInstrumentationFile", nil)
}
