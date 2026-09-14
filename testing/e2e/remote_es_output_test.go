// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build e2e && !requirefips

package e2e

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/testcontainers/testcontainers-go"
)

// TestRemoteESOutputWithSecrets is a regression test for elastic/fleet-server#7794.
//
// It verifies that fleet-server correctly serves a policy with a
// remote_elasticsearch output whose service_token is stored as a Fleet secret
// (non-empty secret_references) without crashing, and that enrolled agents
// successfully apply the policy.
//
// Two agents enroll concurrently so fleet-server dispatches the same policy to
// multiple subscribers simultaneously — the scenario that exercises the shared-
// ParsedPolicy race fixed in #7794.
//
// The service_token is wrapped in {"secrets": {"service_token": "..."}} when
// creating the Fleet output so that Fleet stores it as a secret and populates
// secret_references in the generated policy — the trigger condition for the race.
func (suite *AgentContainerSuite) TestRemoteESOutputWithSecrets() {
	ctx, cancel := context.WithTimeout(suite.T().Context(), 5*time.Minute)
	defer cancel()

	// Start fleet-server container.
	fsReq := testcontainers.ContainerRequest{
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
	fleetC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: fsReq,
		Started:          true,
		Logger:           &logger{suite.T()},
	})
	suite.Require().NoError(err)
	suite.container = fleetC

	endpoint, err := fleetC.Endpoint(ctx, "https")
	suite.Require().NoError(err)
	suite.FleetIsHealthy(ctx, endpoint)

	// Create a service token for the remote ES output.
	serviceToken := suite.CreateServiceToken(ctx)

	// Create the remote_elasticsearch Fleet output. The service_token is wrapped
	// in {"secrets": {...}} so that Fleet stores it as a secret and populates
	// secret_references in the generated policy — the trigger condition for the
	// fleet-server race bug fixed in #7794.
	outputName := "remote-es-" + strings.ReplaceAll(uuid.Must(uuid.NewV4()).String(), "-", "_")
	outputID := suite.CreateFleetOutput(ctx, map[string]any{
		"name":  outputName,
		"type":  "remote_elasticsearch",
		"hosts": []string{"http://elasticsearch:9200"},
		"secrets": map[string]any{
			"service_token": serviceToken,
		},
	})

	// Create an agent policy using the remote ES output as its data output.
	policyID, _ := suite.CreateAgentPolicy(ctx,
		"remote-es-race-"+uuid.Must(uuid.NewV4()).String(),
		"default",
		outputID,
	)

	// Explicitly create an enrollment API key for the new policy.
	// CreateAgentPolicy does not guarantee an auto-generated key is immediately
	// available, so we create one explicitly.
	enrollKey := suite.CreateEnrollmentAPIKey(ctx, policyID)

	// Enroll two agents concurrently under the same policy so that fleet-server
	// dispatches the policy to multiple subscribers simultaneously — the scenario
	// that exercises the shared-ParsedPolicy race fixed in #7794.
	for i := range 2 {
		agentReq := testcontainers.ContainerRequest{
			Image: suite.dockerImg,
			Env: map[string]string{
				"FLEET_ENROLL":           "1",
				"FLEET_URL":              "https://fleet-server:8220",
				"FLEET_CA":               "/tmp/e2e-test-ca.crt",
				"FLEET_ENROLLMENT_TOKEN": enrollKey,
			},
			Networks: []string{"integration_default"},
			Files: []testcontainers.ContainerFile{{
				HostFilePath:      filepath.Join(suite.CertPath, "e2e-test-ca.crt"),
				ContainerFilePath: "/tmp/e2e-test-ca.crt",
				FileMode:          0644,
			}},
		}
		agentC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: agentReq,
			Started:          true,
			Logger:           &logger{suite.T()},
		})
		suite.Require().NoError(err, "agent %d container start failed", i)
		idx := i
		suite.T().Cleanup(func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
			defer cleanupCancel()
			if suite.T().Failed() {
				rc, err := agentC.Logs(cleanupCtx)
				if err != nil {
					suite.T().Logf("unable to get agent %d container logs: %v", idx, err)
				} else {
					p, err := io.ReadAll(rc)
					suite.T().Logf("agent %d container logs (read err: %v):\n%s", idx, err, string(p))
					rc.Close()
				}
			}
			if err := agentC.Terminate(cleanupCtx); err != nil {
				suite.T().Logf("warning: failed to terminate agent %d container: %v", idx, err)
			}
		})
	}

	// Wait for both enrolled agents (any agent that is not the fleet-server agent)
	// to appear in Fleet and reach the online state.
	var firstEnrolledAgentID string
	suite.Require().Eventually(func() bool {
		_, agents := suite.GetAgents(ctx)
		online := 0
		for _, a := range agents {
			if a.ID == suite.agentID {
				continue
			}
			if a.Status == "online" {
				if firstEnrolledAgentID == "" {
					firstEnrolledAgentID = a.ID
				}
				online++
			}
		}
		return online >= 2
	}, 3*time.Minute, time.Second, "fewer than 2 enrolled agents reached online status")

	// Fleet-server must still be healthy after dispatching the policy with
	// secret_references populated to multiple concurrent subscribers — a panic
	// from the race condition would cause the status endpoint to fail.
	suite.FleetServerStatusOK(ctx, endpoint)

	// Verify one enrolled agent's applied policy revision matches Fleet's,
	// confirming fleet-server dispatched the policy without crashing mid-stream.
	suite.Require().Eventually(func() bool {
		agentDoc := suite.GetAgent(ctx, firstEnrolledAgentID)
		policyRevision := suite.GetAgentPolicyRevision(ctx, policyID)
		return agentDoc.Revision >= policyRevision
	}, 2*time.Minute, 5*time.Second, "agent policy revision did not match Fleet's within timeout")
}
