// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	toxiproxy "github.com/Shopify/toxiproxy/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

var longFlag bool

func init() {
	flag.BoolVar(&longFlag, "long", false, "Run long tests.")
}

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(m.Run())
}

// BaseE2ETestSuite contains attributes and methods that are applicable to multiple test cases
type BaseE2ETestSuite struct {
	suite.Suite

	coverPath    string // Path to use as GOCOVERDIR to collect test coverage
	certPath     string // Path to custom certificates and CA
	esHosts      string // comma seperated list of elasticsearch hosts
	serviceToken string // service_token value
	elasticUser  string // user to authenticate to elasticsearch with
	elasticPass  string // password for user authentication

	client *http.Client // http.Client that trusts system CAs and custom CA
}

// Setup sets all attributes in BaseE2ETestSuite
func (suite *BaseE2ETestSuite) Setup() {
	suite.T().Helper()

	// populate cover path
	path, err := filepath.Abs(filepath.Join("..", "..", "build", "e2e-cover"))
	suite.Require().NoError(err)
	suite.coverPath = path
	_, err = os.Stat(suite.coverPath)
	suite.Require().NoError(err)

	// find certs
	path, err = filepath.Abs(filepath.Join("..", "..", "build", "e2e-certs"))
	suite.Require().NoError(err)
	suite.certPath = path
	_, err = os.Stat(suite.certPath)
	suite.Require().NoError(err)

	// get env vars
	v, ok := os.LookupEnv("ELASTICSEARCH_HOSTS")
	suite.Require().True(ok, "expected ELASTICSEARCH_HOSTS to be defined")
	suite.esHosts = v

	v, ok = os.LookupEnv("ELASTICSEARCH_SERVICE_TOKEN")
	suite.Require().True(ok, "expected ELASTICSEARCH_SERVICE_TOKEN to be defined")
	suite.serviceToken = v

	v, ok = os.LookupEnv("ELASTICSEARCH_USERNAME")
	suite.Require().True(ok, "expected ELASTICSEARCH_USERNAME to be defined")
	suite.elasticUser = v

	v, ok = os.LookupEnv("ELASTICSEARCH_PASSWORD")
	suite.Require().True(ok, "expected ELASTICSEARCH_PAASWORD to be defined")
	suite.elasticPass = v

	// create http.Client that trusts system CA and custom CA
	cas, err := x509.SystemCertPool()
	suite.Require().NoError(err)
	p, err := os.ReadFile(filepath.Join(suite.certPath, "e2e-test-ca.crt"))
	suite.Require().NoError(err)
	ok = cas.AppendCertsFromPEM(p)
	suite.Require().True(ok, "failed to add e2e-test-ca.crt to cert pool")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: cas,
		},
	}
	suite.client = &http.Client{Transport: tr}
}

// SetupKibana will issue POST requests to Kibana's fleet API for setup
func (suite *BaseE2ETestSuite) SetupKibana() {
	req, err := http.NewRequest("POST", "http://localhost:5601/api/fleet/setup", nil)
	suite.Require().NoError(err)
	req.SetBasicAuth(suite.elasticUser, suite.elasticPass)
	req.Header.Set("kbn-xsrf", "e2e-setup")

	resp, err := suite.client.Do(req)
	suite.Require().NoError(err)
	resp.Body.Close()
	suite.Require().Equal(http.StatusOK, resp.StatusCode, "unable to setup kibana fleet")

	req, err = http.NewRequest("POST", "http://localhost:5601/api/fleet/agents/setup", nil)
	suite.Require().NoError(err)
	req.SetBasicAuth(suite.elasticUser, suite.elasticPass)
	req.Header.Set("kbn-xsrf", "e2e-setup")

	resp, err = suite.client.Do(req)
	suite.Require().NoError(err)
	resp.Body.Close()
	suite.Require().Equal(http.StatusOK, resp.StatusCode, "unable to setup kibana fleet agents")

	// Need to make a call in order to insert the endpoint package into the security-policy so that it sets everything up correctly
	// If it's defined in the yml it does not load everything, specifically the .fleet-artifacts indices are not created.
	buf := bytes.NewBufferString(`{"name":"Protect","description":"","namespace":"default","policy_id":"security-policy","enabled":true,"inputs":[{"enabled":true,"streams":[],"type":"ENDPOINT_INTEGRATION_CONFIG","config":{"_config":{"value":{"type":"endpoint","endpointConfig":{"preset":"EDRComplete"}}}}}],"package":{"name":"endpoint","title":"Elastic Defend","version":"8.10.2"}}`) // NOTE: Hardcoded package version here

	req, err = http.NewRequest("POST", "http://localhost:5601/api/fleet/package_policies", buf)
	suite.Require().NoError(err)
	req.SetBasicAuth(suite.elasticUser, suite.elasticPass)
	req.Header.Set("kbn-xsrf", "e2e-setup")

	resp, err = suite.client.Do(req)
	suite.Require().NoError(err)
	p, err := io.ReadAll(resp.Body)
	suite.Require().NoError(err)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusConflict {
		suite.Require().Failf("bad status", "expected status of 200 or 409 got %d body %s", resp.StatusCode, string(p))
	}
}

// IsFleetServerPortFree will check if port 8220 is free.
// If it is in use it will poll every second for up to 30s for any change.
func (suite *BaseE2ETestSuite) IsFleetServerPortFree() bool {
	portFree := false
	for i := 0; i < 30; i++ {
		ln, err := net.Listen("tcp", ":8220")
		if err == nil {
			ln.Close()
			portFree = true
			break
		}
		time.Sleep(time.Second)
	}
	return portFree
}

// FleetServerStatusOK will poll fleet-server's status endpoint every second and return when it responds with a 200 status code
// if the passed context terminates before a 200 is returned the current test will be marked as failed.
func (suite *BaseE2ETestSuite) FleetServerStatusOK(ctx context.Context, url string) {
	suite.FleetServerStatusCondition(ctx, url, func(resp *http.Response) bool {
		return resp.StatusCode == http.StatusOK
	})
}

// FleetServerStatusIs will poll fleet-server's status endpoint every second and return when it returns the expected state.
// If the passed context terminates before a 200 is returned the current test will be marked as failed.
func (suite *BaseE2ETestSuite) FleetServerStatusIs(ctx context.Context, url string, state client.UnitState) {
	suite.FleetServerStatusCondition(ctx, url, func(resp *http.Response) bool {
		var status struct {
			Status string `json:"status"`
		}
		d, err := io.ReadAll(resp.Body)
		suite.Require().NoError(err)

		err = json.Unmarshal(d, &status)
		suite.Require().NoError(err)

		return status.Status == state.String()
	})
}

// FleetServerStatusCondition will poll fleet-server's status till the response satisfies the given
// condition.
// If the passed context terminates before, the current test will be marked as failed.
func (suite *BaseE2ETestSuite) FleetServerStatusCondition(ctx context.Context, url string, condition func(resp *http.Response) bool) {
	timer := time.NewTimer(time.Second)
	for {
		select {
		case <-ctx.Done():
			suite.Require().NoError(ctx.Err(), "context expired before status endpoint returned 200")
			return
		case <-timer.C:
			// ping /api/status
			req, err := http.NewRequestWithContext(ctx, "GET", url+"/api/status", nil)
			suite.Require().NoError(err)

			resp, err := suite.client.Do(req)
			if err != nil {
				timer.Reset(time.Second)
				continue
			}

			// on success
			if condition(resp) {
				resp.Body.Close()
				return
			}
			resp.Body.Close()

			// fail, try after a wait
			timer.Reset(time.Second)
		}
	}
}

// AgentIsOnline will check Kibana if the agent specified by the passed id has the online status.
// The test is marked as failed if the passed context terminates before that.
func (suite *BaseE2ETestSuite) AgentIsOnline(ctx context.Context, id string) {
	timer := time.NewTimer(time.Second)
	for {
		select {
		case <-ctx.Done():
			suite.Require().NoError(ctx.Err(), "context expired before agent reported online")
			return
		case <-timer.C:
			req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost:5601/api/fleet/agents/"+id, nil)
			suite.Require().NoError(err)
			req.SetBasicAuth(suite.elasticUser, suite.elasticPass)
			req.Header.Set("kbn-xsrf", "e2e-setup")

			resp, err := suite.client.Do(req)
			suite.Require().NoError(err)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				timer.Reset(time.Second)
				continue
			}

			var obj struct {
				Item struct {
					Status string `json:"status"`
				} `json:"item"`
			}
			err = json.NewDecoder(resp.Body).Decode(&obj)
			suite.Require().NoError(err)
			if obj.Item.Status == "online" {
				return
			}
			timer.Reset(time.Second)
		}
	}
}

// NewFleetIsOnline will check Kibana if the 1st entry in the agents list has the online status.
// The test is marked as failed if the passed context terminates before that.
// The associated agent ID is returned.
// It is intended to be used immediatly after a fleet-server that's managed by an agent is enrolled (as it would be the only item on the list).
func (suite *BaseE2ETestSuite) NewFleetIsOnline(ctx context.Context) string {
	timer := time.NewTimer(time.Second)
	for {
		select {
		case <-ctx.Done():
			suite.Require().NoError(ctx.Err(), "context expired before agent reported online")
			return ""
		case <-timer.C:
			status, agents := suite.getAgents(ctx)
			if status != http.StatusOK {
				timer.Reset(time.Second)
				continue
			}

			if len(agents) < 1 {
				timer.Reset(time.Second)
				continue
			}
			if agents[0].Status == "online" {
				return agents[0].ID
			}
			timer.Reset(time.Second)
		}
	}
}

// KibanaAgent is the structure used to describe an agent in Kibana
type KibanaAgent struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

func (suite *BaseE2ETestSuite) getAgents(ctx context.Context) (int, []KibanaAgent) {
	// TODO handle pagination if needed in the future
	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost:5601/api/fleet/agents", nil)
	suite.Require().NoError(err)
	req.SetBasicAuth(suite.elasticUser, suite.elasticPass)
	req.Header.Set("kbn-xsrf", "e2e-setup")

	resp, err := suite.client.Do(req)
	suite.Require().NoError(err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}

	var obj struct {
		Items []KibanaAgent `json:"items"`
	}
	err = json.NewDecoder(resp.Body).Decode(&obj)
	suite.Require().NoError(err)
	return resp.StatusCode, obj.Items
}

// DeleteAllAgents will remove all agents from Kibana.
func (suite *BaseE2ETestSuite) DeleteAllAgents(ctx context.Context) {
	status, agents := suite.getAgents(ctx)
	suite.Require().Equal(http.StatusOK, status)
	for _, agent := range agents {
		req, err := http.NewRequestWithContext(ctx, "DELETE", "http://localhost:5601/api/fleet/agents/"+agent.ID, nil)
		suite.Require().NoError(err)
		req.SetBasicAuth(suite.elasticUser, suite.elasticPass)
		req.Header.Set("kbn-xsrf", "e2e-setup")

		resp, err := suite.client.Do(req)
		suite.Require().NoError(err)
		resp.Body.Close()
		suite.Require().Equalf(http.StatusOK, resp.StatusCode, "Unable to delete agent %q", agent.ID)
	}
}

// GetEnrollmentTokenForPolicyID will use Kibana's fleet API to return the first enrollment token associated with the specified policy ID.
func (suite *BaseE2ETestSuite) GetEnrollmentTokenForPolicyID(ctx context.Context, id string) string {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost:5601/api/fleet/enrollment_api_keys", nil)
	suite.Require().NoError(err)

	req.SetBasicAuth(suite.elasticUser, suite.elasticPass)
	req.Header.Set("kbn-xsrf", "e2e-setup")

	resp, err := suite.client.Do(req)
	suite.Require().NoError(err)
	defer resp.Body.Close()

	suite.Require().Equal(http.StatusOK, resp.StatusCode, "unable to get enrollment keys")
	var obj struct {
		Items []struct {
			APIKey   string `json:"api_key"`
			PolicyID string `json:"policy_id"`
		} `json:"items"`
	}

	err = json.NewDecoder(resp.Body).Decode(&obj)
	suite.Require().NoError(err)

	for _, key := range obj.Items {
		if key.PolicyID == id {
			return key.APIKey
		}
	}
	suite.Require().Failf("unable to find enrollment key for ID %s", id)
	return ""
}

// RequestDiagnosticsForAgent will use Kibana's fleet API to request a diagnostics action for the specified agent ID and return the associated ActionID.
func (suite *BaseE2ETestSuite) RequestDiagnosticsForAgent(ctx context.Context, id string) string {
	req, err := http.NewRequestWithContext(ctx, "POST", "http://localhost:5601/api/fleet/agents/"+id+"/request_diagnostics", nil)
	suite.Require().NoError(err)
	req.SetBasicAuth(suite.elasticUser, suite.elasticPass)
	req.Header.Set("kbn-xsrf", "e2e-setup")
	resp, err := suite.client.Do(req)
	suite.Require().NoError(err)
	suite.Require().Equal(http.StatusOK, resp.StatusCode)

	var obj struct {
		ActionID string `json:"actionId"`
	}
	err = json.NewDecoder(resp.Body).Decode(&obj)
	suite.Require().NoError(err)
	resp.Body.Close()
	suite.Require().NotEmpty(obj.ActionID)
	return obj.ActionID
}

// VerifyAgentInKibana checks Kibana's fleet API for the specified agent.
func (suite *BaseE2ETestSuite) VerifyAgentInKibana(ctx context.Context, id string) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost:5601/api/fleet/agents/"+id, nil)
	suite.Require().NoError(err)
	req.SetBasicAuth(suite.elasticUser, suite.elasticPass)
	req.Header.Set("kbn-xsrf", "e2e-setup")
	resp, err := suite.client.Do(req)
	suite.Require().NoError(err)
	resp.Body.Close()
	suite.Require().Equal(http.StatusOK, resp.StatusCode, "expected to find agent in fleet api")
}

// AddSecurityContainer ensures that a trusted app list exists for endpoint.
//
// This is used to test the artifacts endpoint.
func (suite *BaseE2ETestSuite) AddSecurityContainer(ctx context.Context) {
	b := bytes.NewBufferString(`{  "description": "Elastic Defend Trusted Apps List",
            "name": "Elastic Defend Trusted Apps List",
            "list_id": "endpoint_trusted_apps",
            "type": "endpoint",
            "namespace_type": "agnostic"}`)
	req, err := http.NewRequestWithContext(ctx, "POST", "http://localhost:5601/api/exception_lists", b)
	suite.Require().NoError(err)
	req.SetBasicAuth(suite.elasticUser, suite.elasticPass)
	req.Header.Set("kbn-xsrf", "e2e-setup")
	resp, err := suite.client.Do(req)
	suite.Require().NoError(err)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusConflict {
		suite.Require().Failf("bad status", "status of 200 or 409 expected got %d", resp.StatusCode)
	}
}

// AddSecurityContainerItem adds an item to endpoint's trusted app list.
//
// This is used to test the artifacts endpoint.
func (suite *BaseE2ETestSuite) AddSecurityContainerItem(ctx context.Context) string {
	b := bytes.NewBufferString(`{
          "description": "TEST",
          "entries": [{
            "field": "process.executable.caseless",
            "value": "/bin/bash",
            "type": "match",
            "operator": "included"
          }],
          "list_id": "endpoint_trusted_apps",
          "name": "TEST",
          "namespace_type": "agnostic",
          "os_types": ["linux"],
          "type": "simple"
        }`)
	req, err := http.NewRequestWithContext(ctx, "POST", "http://localhost:5601/api/exception_lists/items", b)
	suite.Require().NoError(err)
	req.SetBasicAuth(suite.elasticUser, suite.elasticPass)
	req.Header.Set("kbn-xsrf", "e2e-setup")
	resp, err := suite.client.Do(req)
	suite.Require().NoError(err)
	defer resp.Body.Close()
	suite.Require().Equal(http.StatusOK, resp.StatusCode)
	var obj struct {
		ID string `json:"id"`
	}
	err = json.NewDecoder(resp.Body).Decode(&obj)
	suite.Require().NoError(err)
	return obj.ID
}

// ArtifactHit represents a hit when searching the .fleet-artifacts-* indices.
type ArtifactHit struct {
	Source struct {
		Identifier    string `json:"identifier"`
		DecodedSHA256 string `json:"decoded_sha256"`
		EncodedSHA256 string `json:"encoded_sha256"`
	} `json:"_source"`
}

// FleetHasArtifacts searches the .fleet-artifacts indecies for an "endpoint-trustlist-linux-v1" entry and returns when a hit is found.
// If the passed context terminates before a hit is found the current test is marked as failed.
func (suite *BaseE2ETestSuite) FleetHasArtifacts(ctx context.Context) []ArtifactHit {
	timer := time.NewTimer(time.Second)
	for {
		buf := bytes.NewBufferString(`{"query":{"match":{"identifier":"endpoint-trustlist-linux-v1"}}}`)
		req, err := http.NewRequestWithContext(ctx, "POST", "http://localhost:9200/.fleet-artifacts-*/_search", buf)
		suite.Require().NoError(err)
		req.SetBasicAuth(suite.elasticUser, suite.elasticPass)
		req.Header.Set("Content-Type", "application/json")
		select {
		case <-ctx.Done():
			suite.Require().NoError(ctx.Err(), "context expired before artifact was detected in index")
			return nil
		case <-timer.C:
			resp, err := suite.client.Do(req)
			suite.Require().NoError(err)
			if resp.StatusCode != http.StatusOK {
				timer.Reset(time.Second)
				continue
			}

			var obj struct {
				Hits struct {
					Hits  []ArtifactHit `json:"hits"`
					Total struct {
						Value int `json:"value"`
					} `json:"total"`
				} `json:"hits"`
			}
			err = json.NewDecoder(resp.Body).Decode(&obj)
			resp.Body.Close()
			suite.Require().NoError(err)
			if obj.Hits.Total.Value > 0 {
				return obj.Hits.Hits
			}
			timer.Reset(time.Second)
		}
	}
}

func (suite *BaseE2ETestSuite) StartToxiproxy(ctx context.Context) *toxiproxy.Client {
	req := testcontainers.ContainerRequest{
		Image:        "ghcr.io/shopify/toxiproxy:2.5.0",
		ExposedPorts: []string{"8474/tcp"},
		WaitingFor:   wait.ForHTTP("/version").WithPort("8474/tcp"),
		NetworkMode:  "host",
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	suite.Require().NoError(err)

	suite.T().Cleanup(func() {
		err := container.Terminate(context.Background())
		if err != nil {
			suite.T().Log("could not terminate toxiproxy container")
		}
	})

	mappedPort, err := container.MappedPort(ctx, "8474")
	suite.Require().NoError(err)

	hostIP, err := container.Host(ctx)
	suite.Require().NoError(err)

	endpoint := fmt.Sprintf("%s:%s", hostIP, mappedPort.Port())
	return toxiproxy.NewClient(endpoint)
}

func containerWaitForHealthyStatus() *wait.HTTPStrategy {
	matcher := func(body io.Reader) bool {
		d, err := io.ReadAll(body)
		if err != nil {
			return false
		}
		var status struct {
			Status string `json:"status"`
		}
		err = json.Unmarshal(d, &status)
		if err != nil {
			return false
		}
		return status.Status == "HEALTHY"
	}
	return wait.ForHTTP("/api/status").
		WithResponseMatcher(matcher).
		WithAllowInsecure(true).
		WithPort("8220/tcp")
}
