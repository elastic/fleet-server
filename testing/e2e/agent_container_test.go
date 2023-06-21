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

	"github.com/elastic/fleet-server/testing/e2e/api_version"
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

	suite.FleetIsHealthy(ctx, endpoint)
}

func (suite *AgentContainerSuite) TestWithSecretFiles() {
	// Create a service token file in the temp test dir
	dir := suite.T().TempDir()
	err := os.WriteFile(filepath.Join(dir, "service-token"), []byte(suite.serviceToken), 0644)
	suite.Require().NoError(err)

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
			HostFilePath:      filepath.Join(suite.certPath, "e2e-test-ca.crt"),
			ContainerFilePath: "/tmp/e2e-test-ca.crt",
			FileMode:          0644,
		}, {
			HostFilePath:      filepath.Join(suite.certPath, "fleet-server.crt"),
			ContainerFilePath: "/tmp/fleet-server.crt",
			FileMode:          0644,
		}, {
			HostFilePath:      filepath.Join(suite.certPath, "fleet-server.key"),
			ContainerFilePath: "/tmp/fleet-server.key",
			FileMode:          0644,
		}, {
			HostFilePath:      filepath.Join(suite.certPath, "passphrase"),
			ContainerFilePath: "/tmp/passphrase",
			FileMode:          0644,
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

	suite.FleetIsHealthy(ctx, endpoint)
}

func (suite *AgentContainerSuite) TestClientAPI() {
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
			"FLEET_SERVER_SERVICE_TOKEN":       suite.serviceToken,
			"FLEET_SERVER_ELASTICSEARCH_HOST":  "http://elasticsearch:9200",
			"FLEET_SERVER_POLICY_ID":           "fleet-server-policy",
		},
		ExposedPorts: []string{"8220/tcp"},
		Networks:     []string{"integration_default"},
		// certs are copied so they can be readable by fleet-server.
		Files: []testcontainers.ContainerFile{{
			HostFilePath:      filepath.Join(suite.certPath, "e2e-test-ca.crt"),
			ContainerFilePath: "/tmp/e2e-test-ca.crt",
			FileMode:          0644,
		}, {
			HostFilePath:      filepath.Join(suite.certPath, "fleet-server.crt"),
			ContainerFilePath: "/tmp/fleet-server.crt",
			FileMode:          0644,
		}, {
			HostFilePath:      filepath.Join(suite.certPath, "fleet-server.key"),
			ContainerFilePath: "/tmp/fleet-server.key",
			FileMode:          0644,
		}, {
			HostFilePath:      filepath.Join(suite.certPath, "passphrase"),
			ContainerFilePath: "/tmp/passphrase",
			FileMode:          0644,
		}},
		Mounts: testcontainers.ContainerMounts{
			testcontainers.ContainerMount{
				Source: &testcontainers.GenericBindMountSource{suite.coverPath},
				Target: "/cover",
			},
		},
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

	// Run subtests
	suite.Run("test status unauthenicated", func() {
		ctx, cancel := context.WithCancel(bCtx)
		defer cancel()
		tester := api_version.NewClientAPITesterCurrent(
			suite.Suite,
			ctx,
			suite.client,
			endpoint,
		)
		tester.TestStatus("")
	})

	suite.Run("test status authenicated", func() {
		ctx, cancel := context.WithCancel(bCtx)
		defer cancel()
		tester := api_version.NewClientAPITesterCurrent(
			suite.Suite,
			ctx,
			suite.client,
			endpoint,
		)
		tester.TestStatus(enrollmentKey)
	})

	suite.Run("test enroll checkin ack", func() {
		ctx, cancel := context.WithTimeout(bCtx, 3*time.Minute)
		defer cancel()
		tester := api_version.NewClientAPITesterCurrent(
			suite.Suite,
			ctx,
			suite.client,
			endpoint,
		)

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

		defer cancel()

		tester.TestCheckin(agentKey, agentID, ackToken, &dur)

		// sanity check agent status in kibana
		suite.AgentIsOnline(ctx, agentID)
	})

	suite.Run("test file upload", func() {
		ctx, cancel := context.WithCancel(bCtx)
		defer cancel()
		tester := api_version.NewClientAPITesterCurrent(
			suite.Suite,
			ctx,
			suite.client,
			endpoint,
		)
		agentID, agentKey := tester.TestEnroll(enrollmentKey)
		actionID := suite.RequestDiagnosticsForAgent(ctx, agentID)

		tester.TestFullFileUpload(agentKey, agentID, actionID, 8192) // 8KiB file
	})

	suite.Run("test artifact", func() {
		ctx, cancel := context.WithTimeout(bCtx, 3*time.Minute)
		defer cancel()
		tester := api_version.NewClientAPITesterCurrent(
			suite.Suite,
			ctx,
			suite.client,
			endpoint,
		)
		_, agentKey := tester.TestEnroll(enrollmentKey)
		suite.AddSecurityContainer(ctx)
		suite.AddSecurityContainerItem(ctx)

		hits := suite.FleetHasArtifacts(ctx)
		tester.TestArtifact(agentKey, hits[0].Source.Identifier, hits[0].Source.DecodedSHA256, hits[0].Source.EncodedSHA256)
	})
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
			"FLEET_SERVER_SERVICE_TOKEN":       suite.serviceToken,
			"FLEET_SERVER_ELASTICSEARCH_HOST":  "http://elasticsearch:9200",
			"FLEET_SERVER_POLICY_ID":           "fleet-server-policy",
		},
		ExposedPorts: []string{"8220/tcp"},
		Networks:     []string{"integration_default"},
		// certs are copied so they can be readable by fleet-server.
		Files: []testcontainers.ContainerFile{{
			HostFilePath:      filepath.Join(suite.certPath, "e2e-test-ca.crt"),
			ContainerFilePath: "/tmp/e2e-test-ca.crt",
			FileMode:          0644,
		}, {
			HostFilePath:      filepath.Join(suite.certPath, "fleet-server.crt"),
			ContainerFilePath: "/tmp/fleet-server.crt",
			FileMode:          0644,
		}, {
			HostFilePath:      filepath.Join(suite.certPath, "fleet-server.key"),
			ContainerFilePath: "/tmp/fleet-server.key",
			FileMode:          0644,
		}, {
			HostFilePath:      filepath.Join(suite.certPath, "passphrase"),
			ContainerFilePath: "/tmp/passphrase",
			FileMode:          0644,
		}},
		Mounts: testcontainers.ContainerMounts{
			testcontainers.ContainerMount{
				Source: &testcontainers.GenericBindMountSource{suite.coverPath},
				Target: "/cover",
			},
		},
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
			"FLEET_SERVER_SERVICE_TOKEN":       suite.serviceToken,
			"FLEET_SERVER_ELASTICSEARCH_HOST":  "http://elasticsearch:9200",
			"FLEET_SERVER_POLICY_ID":           "fleet-server-policy",
		},
		ExposedPorts: []string{"8220/tcp"},
		Networks:     []string{"integration_default"},
		// certs are copied so they can be readable by fleet-server.
		Files: []testcontainers.ContainerFile{{
			HostFilePath:      filepath.Join(suite.certPath, "e2e-test-ca.crt"),
			ContainerFilePath: "/tmp/e2e-test-ca.crt",
			FileMode:          0644,
		}, {
			HostFilePath:      filepath.Join(suite.certPath, "fleet-server.crt"),
			ContainerFilePath: "/tmp/fleet-server.crt",
			FileMode:          0644,
		}, {
			HostFilePath:      filepath.Join(suite.certPath, "fleet-server.key"),
			ContainerFilePath: "/tmp/fleet-server.key",
			FileMode:          0644,
		}, {
			HostFilePath:      filepath.Join(suite.certPath, "passphrase"),
			ContainerFilePath: "/tmp/passphrase",
			FileMode:          0644,
		}},
		Mounts: testcontainers.ContainerMounts{
			testcontainers.ContainerMount{
				Source: &testcontainers.GenericBindMountSource{suite.coverPath},
				Target: "/cover",
			},
		},
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
			HostFilePath:      filepath.Join(suite.certPath, "e2e-test-ca.crt"),
			ContainerFilePath: "/tmp/e2e-test-ca.crt",
			FileMode:          0644,
		}},
		Mounts: testcontainers.ContainerMounts{
			testcontainers.ContainerMount{
				Source: &testcontainers.GenericBindMountSource{suite.coverPath},
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
				status, agents := suite.getAgents(ctx)
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
