// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build e2e

package scaffold

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"

	toxiproxy "github.com/Shopify/toxiproxy/client"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Scaffold contains attributes and methods that are applicable to multiple test cases
type Scaffold struct {
	suite.Suite

	CoverPath    string // Path to use as GOCOVERDIR to collect test coverage
	CertPath     string // Path to custom certificates and CA
	ESHosts      string // comma seperated list of elasticsearch hosts
	ServiceToken string // service_token value
	ElasticUser  string // user to authenticate to elasticsearch with
	ElasticPass  string // password for user authentication

	Client *http.Client // http.Client that trusts system CAs and custom CA
}

// Setup sets all attributes in Scaffold
func (s *Scaffold) Setup() {
	s.T().Helper()

	// populate cover path
	path, err := filepath.Abs(filepath.Join("..", "..", "build", "e2e-cover"))
	s.Require().NoError(err)
	s.CoverPath = path
	_, err = os.Stat(s.CoverPath)
	s.Require().NoError(err)

	// find certs
	path, err = filepath.Abs(filepath.Join("..", "..", "build", "e2e-certs"))
	s.Require().NoError(err)
	s.CertPath = path
	_, err = os.Stat(s.CertPath)
	s.Require().NoError(err)

	// get env vars
	v, ok := os.LookupEnv("ELASTICSEARCH_HOSTS")
	s.Require().True(ok, "expected ELASTICSEARCH_HOSTS to be defined")
	s.ESHosts = v

	v, ok = os.LookupEnv("ELASTICSEARCH_SERVICE_TOKEN")
	s.Require().True(ok, "expected ELASTICSEARCH_SERVICE_TOKEN to be defined")
	s.ServiceToken = v

	v, ok = os.LookupEnv("ELASTICSEARCH_USERNAME")
	s.Require().True(ok, "expected ELASTICSEARCH_USERNAME to be defined")
	s.ElasticUser = v

	v, ok = os.LookupEnv("ELASTICSEARCH_PASSWORD")
	s.Require().True(ok, "expected ELASTICSEARCH_PAASWORD to be defined")
	s.ElasticPass = v

	// create http.Client that trusts system CA and custom CA
	cas, err := x509.SystemCertPool()
	s.Require().NoError(err)
	p, err := os.ReadFile(filepath.Join(s.CertPath, "e2e-test-ca.crt"))
	s.Require().NoError(err)
	ok = cas.AppendCertsFromPEM(p)
	s.Require().True(ok, "failed to add e2e-test-ca.crt to cert pool")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: cas,
		},
	}
	s.Client = &http.Client{Transport: tr}
}

// SetupKibana will issue POST requests to Kibana's fleet API for setup
func (s *Scaffold) SetupKibana() {
	req, err := http.NewRequest("POST", "http://localhost:5601/api/fleet/setup", nil)
	s.Require().NoError(err)
	req.SetBasicAuth(s.ElasticUser, s.ElasticPass)
	req.Header.Set("kbn-xsrf", "e2e-setup")

	resp, err := s.Client.Do(req)
	s.Require().NoError(err)
	resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode, "unable to setup kibana fleet")

	req, err = http.NewRequest("POST", "http://localhost:5601/api/fleet/agents/setup", nil)
	s.Require().NoError(err)
	req.SetBasicAuth(s.ElasticUser, s.ElasticPass)
	req.Header.Set("kbn-xsrf", "e2e-setup")

	resp, err = s.Client.Do(req)
	s.Require().NoError(err)
	resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode, "unable to setup kibana fleet agents")

	// Need to make a call in order to insert the endpoint package into the security-policy so that it sets everything up correctly
	// If it's defined in the yml it does not load everything, specifically the .fleet-artifacts indices are not created.
	buf := bytes.NewBufferString(`{"name":"Protect","description":"","namespace":"default","policy_id":"security-policy","enabled":true,"inputs":[{"enabled":true,"streams":[],"type":"ENDPOINT_INTEGRATION_CONFIG","config":{"_config":{"value":{"type":"endpoint","endpointConfig":{"preset":"EDRComplete"}}}}}],"package":{"name":"endpoint","title":"Elastic Defend","version":"8.10.0"}}`) // NOTE: Hardcoded package version here

	req, err = http.NewRequest("POST", "http://localhost:5601/api/fleet/package_policies", buf)
	s.Require().NoError(err)
	req.SetBasicAuth(s.ElasticUser, s.ElasticPass)
	req.Header.Set("kbn-xsrf", "e2e-setup")

	resp, err = s.Client.Do(req)
	s.Require().NoError(err)
	p, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusConflict {
		s.Require().Failf("bad status", "expected status of 200 or 409 got %d body %s", resp.StatusCode, string(p))
	}
}

// IsFleetServerPortFree will check if port 8220 is free.
// If it is in use it will poll every second for up to 30s for any change.
func (s *Scaffold) IsFleetServerPortFree() bool {
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
func (s *Scaffold) FleetServerStatusOK(ctx context.Context, url string) {
	s.FleetServerStatusCondition(ctx, url, func(resp *http.Response) bool {
		return resp.StatusCode == http.StatusOK
	})
}

// FleetServerStatusIs will poll fleet-server's status endpoint every second and return when it returns the expected state.
// If the passed context terminates before a 200 is returned the current test will be marked as failed.
func (s *Scaffold) FleetServerStatusIs(ctx context.Context, url string, state client.UnitState) {
	s.FleetServerStatusCondition(ctx, url, func(resp *http.Response) bool {
		var status struct {
			Status string `json:"status"`
		}
		d, err := io.ReadAll(resp.Body)
		s.Require().NoError(err)

		err = json.Unmarshal(d, &status)
		s.Require().NoError(err)

		return status.Status == state.String()
	})
}

// FleetServerStatusCondition will poll fleet-server's status till the response satisfies the given
// condition.
// If the passed context terminates before, the current test will be marked as failed.
func (s *Scaffold) FleetServerStatusCondition(ctx context.Context, url string, condition func(resp *http.Response) bool) {
	timer := time.NewTimer(time.Second)
	for {
		select {
		case <-ctx.Done():
			s.Require().NoError(ctx.Err(), "context expired before status endpoint returned 200")
			return
		case <-timer.C:
			// ping /api/status
			req, err := http.NewRequestWithContext(ctx, "GET", url+"/api/status", nil)
			s.Require().NoError(err)

			resp, err := s.Client.Do(req)
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
func (s *Scaffold) AgentIsOnline(ctx context.Context, id string) {
	timer := time.NewTimer(time.Second)
	for {
		select {
		case <-ctx.Done():
			s.Require().NoError(ctx.Err(), "context expired before agent reported online")
			return
		case <-timer.C:
			req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost:5601/api/fleet/agents/"+id, nil)
			s.Require().NoError(err)
			req.SetBasicAuth(s.ElasticUser, s.ElasticPass)
			req.Header.Set("kbn-xsrf", "e2e-setup")

			resp, err := s.Client.Do(req)
			s.Require().NoError(err)
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
			s.Require().NoError(err)
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
func (s *Scaffold) NewFleetIsOnline(ctx context.Context) string {
	timer := time.NewTimer(time.Second)
	for {
		select {
		case <-ctx.Done():
			s.Require().NoError(ctx.Err(), "context expired before agent reported online")
			return ""
		case <-timer.C:
			status, agents := s.GetAgents(ctx)
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

func (s *Scaffold) GetAgents(ctx context.Context) (int, []KibanaAgent) {
	// TODO handle pagination if needed in the future
	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost:5601/api/fleet/agents", nil)
	s.Require().NoError(err)
	req.SetBasicAuth(s.ElasticUser, s.ElasticPass)
	req.Header.Set("kbn-xsrf", "e2e-setup")

	resp, err := s.Client.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}

	var obj struct {
		Items []KibanaAgent `json:"items"`
	}
	err = json.NewDecoder(resp.Body).Decode(&obj)
	s.Require().NoError(err)
	return resp.StatusCode, obj.Items
}

// DeleteAllAgents will remove all agents from Kibana.
func (s *Scaffold) DeleteAllAgents(ctx context.Context) {
	status, agents := s.GetAgents(ctx)
	s.Require().Equal(http.StatusOK, status)
	for _, agent := range agents {
		req, err := http.NewRequestWithContext(ctx, "DELETE", "http://localhost:5601/api/fleet/agents/"+agent.ID, nil)
		s.Require().NoError(err)
		req.SetBasicAuth(s.ElasticUser, s.ElasticPass)
		req.Header.Set("kbn-xsrf", "e2e-setup")

		resp, err := s.Client.Do(req)
		s.Require().NoError(err)
		resp.Body.Close()
		s.Require().Equalf(http.StatusOK, resp.StatusCode, "Unable to delete agent %q", agent.ID)
	}
}

// GetEnrollmentTokenForPolicyID will use Kibana's fleet API to return the first enrollment token associated with the specified policy ID.
func (s *Scaffold) GetEnrollmentTokenForPolicyID(ctx context.Context, id string) string {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost:5601/api/fleet/enrollment_api_keys", nil)
	s.Require().NoError(err)

	req.SetBasicAuth(s.ElasticUser, s.ElasticPass)
	req.Header.Set("kbn-xsrf", "e2e-setup")

	resp, err := s.Client.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusOK, resp.StatusCode, "unable to get enrollment keys")
	var obj struct {
		Items []struct {
			APIKey   string `json:"api_key"`
			PolicyID string `json:"policy_id"`
		} `json:"items"`
	}

	err = json.NewDecoder(resp.Body).Decode(&obj)
	s.Require().NoError(err)

	for _, key := range obj.Items {
		if key.PolicyID == id {
			return key.APIKey
		}
	}
	s.Require().Failf("unable to find enrollment key for ID %s", id)
	return ""
}

// RequestDiagnosticsForAgent will use Kibana's fleet API to request a diagnostics action for the specified agent ID and return the associated ActionID.
func (s *Scaffold) RequestDiagnosticsForAgent(ctx context.Context, id string) string {
	req, err := http.NewRequestWithContext(ctx, "POST", "http://localhost:5601/api/fleet/agents/"+id+"/request_diagnostics", nil)
	s.Require().NoError(err)
	req.SetBasicAuth(s.ElasticUser, s.ElasticPass)
	req.Header.Set("kbn-xsrf", "e2e-setup")
	resp, err := s.Client.Do(req)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, resp.StatusCode)

	var obj struct {
		ActionID string `json:"actionId"`
	}
	err = json.NewDecoder(resp.Body).Decode(&obj)
	s.Require().NoError(err)
	resp.Body.Close()
	s.Require().NotEmpty(obj.ActionID)
	return obj.ActionID
}

// VerifyAgentInKibana checks Kibana's fleet API for the specified agent.
func (s *Scaffold) VerifyAgentInKibana(ctx context.Context, id string) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost:5601/api/fleet/agents/"+id, nil)
	s.Require().NoError(err)
	req.SetBasicAuth(s.ElasticUser, s.ElasticPass)
	req.Header.Set("kbn-xsrf", "e2e-setup")
	resp, err := s.Client.Do(req)
	s.Require().NoError(err)
	resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode, "expected to find agent in fleet api")
}

// AddSecurityContainer ensures that a trusted app list exists for endpoint.
//
// This is used to test the artifacts endpoint.
func (s *Scaffold) AddSecurityContainer(ctx context.Context) {
	b := bytes.NewBufferString(`{  "description": "Elastic Defend Trusted Apps List",
            "name": "Elastic Defend Trusted Apps List",
            "list_id": "endpoint_trusted_apps",
            "type": "endpoint",
            "namespace_type": "agnostic"}`)
	req, err := http.NewRequestWithContext(ctx, "POST", "http://localhost:5601/api/exception_lists", b)
	s.Require().NoError(err)
	req.SetBasicAuth(s.ElasticUser, s.ElasticPass)
	req.Header.Set("kbn-xsrf", "e2e-setup")
	resp, err := s.Client.Do(req)
	s.Require().NoError(err)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusConflict {
		s.Require().Failf("bad status", "status of 200 or 409 expected got %d", resp.StatusCode)
	}
}

// AddSecurityContainerItem adds an item to endpoint's trusted app list.
//
// This is used to test the artifacts endpoint.
func (s *Scaffold) AddSecurityContainerItem(ctx context.Context) string {
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
	s.Require().NoError(err)
	req.SetBasicAuth(s.ElasticUser, s.ElasticPass)
	req.Header.Set("kbn-xsrf", "e2e-setup")
	resp, err := s.Client.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)
	var obj struct {
		ID string `json:"id"`
	}
	err = json.NewDecoder(resp.Body).Decode(&obj)
	s.Require().NoError(err)
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
func (s *Scaffold) FleetHasArtifacts(ctx context.Context) []ArtifactHit {
	timer := time.NewTimer(time.Second)
	for {
		buf := bytes.NewBufferString(`{"query":{"match":{"identifier":"endpoint-trustlist-linux-v1"}}}`)
		req, err := http.NewRequestWithContext(ctx, "POST", "http://localhost:9200/.fleet-artifacts-*/_search", buf)
		s.Require().NoError(err)
		req.SetBasicAuth(s.ElasticUser, s.ElasticPass)
		req.Header.Set("Content-Type", "application/json")
		select {
		case <-ctx.Done():
			s.Require().NoError(ctx.Err(), "context expired before artifact was detected in index")
			return nil
		case <-timer.C:
			resp, err := s.Client.Do(req)
			s.Require().NoError(err)
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
			s.Require().NoError(err)
			if obj.Hits.Total.Value > 0 {
				return obj.Hits.Hits
			}
			timer.Reset(time.Second)
		}
	}
}

func (s *Scaffold) StartToxiproxy(ctx context.Context) *toxiproxy.Client {
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
	s.Require().NoError(err)

	s.T().Cleanup(func() {
		err := container.Terminate(context.Background())
		if err != nil {
			s.T().Log("could not terminate toxiproxy container")
		}
	})

	mappedPort, err := container.MappedPort(ctx, "8474")
	s.Require().NoError(err)

	hostIP, err := container.Host(ctx)
	s.Require().NoError(err)

	endpoint := fmt.Sprintf("%s:%s", hostIP, mappedPort.Port())
	return toxiproxy.NewClient(endpoint)
}
