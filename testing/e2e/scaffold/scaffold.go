// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

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
	"strings"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"

	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	toxitc "github.com/testcontainers/testcontainers-go/modules/toxiproxy"
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
	s.Require().True(ok, "expected ELASTICSEARCH_PASSWORD to be defined")
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
	}, true)
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
	}, true)
}

// FleetServerStatusIs will poll fleet-server's status endpoint every second and return when it returns the expected state.
// If the passed context terminates before a 200 is returned the current test will be marked as failed.
func (s *Scaffold) FleetServerStatusNeverBecomes(ctx context.Context, url string, state client.UnitState) {
	s.FleetServerStatusCondition(ctx, url, func(resp *http.Response) bool {
		var status struct {
			Status string `json:"status"`
		}
		d, err := io.ReadAll(resp.Body)
		s.Require().NoError(err)

		err = json.Unmarshal(d, &status)
		s.Require().NoError(err)

		s.NotEqual(state.String(), status.Status)
		return false
	}, false)
}

// FleetServerStatusCondition will poll fleet-server's status till the response satisfies the given
// condition.
// If the passed context terminates before, the current test will be marked as failed.
func (s *Scaffold) FleetServerStatusCondition(ctx context.Context, url string, condition func(resp *http.Response) bool, failOnDone bool) {
	timer := time.NewTimer(time.Second)
	for {
		select {
		case <-ctx.Done():
			if failOnDone {
				s.Require().NoError(ctx.Err(), "context expired before status endpoint returned 200")
			}
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
	s.AgentHasStatus(ctx, id, "online")
}

func (s *Scaffold) AgentIsUpdating(ctx context.Context, id string) {
	s.AgentHasStatus(ctx, id, "updating")
}

// AgentHasStatus polls Kibana's Fleet API until the agent with the given ID has one of the
// specified statuses.
func (s *Scaffold) AgentHasStatus(ctx context.Context, id string, statuses ...string) {
	timer := time.NewTimer(time.Second)
	for {
		select {
		case <-ctx.Done():
			s.Require().NoError(ctx.Err(), "context expired before agent reached expected status")
			return
		case <-timer.C:
			req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost:5601/api/fleet/agents/"+id, nil)
			s.Require().NoError(err)
			req.SetBasicAuth(s.ElasticUser, s.ElasticPass)
			req.Header.Set("kbn-xsrf", "e2e-setup")

			resp, err := s.Client.Do(req)
			s.Require().NoError(err, "kibana agent request failure")
			if resp.StatusCode != http.StatusOK {
				timer.Reset(time.Second)
				resp.Body.Close()
				continue
			}

			p, err := io.ReadAll(resp.Body)
			s.Require().NoError(err, "unable to read kibana agent response")
			resp.Body.Close()

			var obj struct {
				Item struct {
					Status string `json:"status"`
				} `json:"item"`
			}
			s.T().Logf("Kibana agent response: %s", string(p))
			err = json.Unmarshal(p, &obj)
			s.Require().NoError(err, "unmarshal failure")
			for _, status := range statuses {
				if obj.Item.Status == status {
					return
				}
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

type ESAgentDoc struct {
	Revision      int    `json:"policy_revision_idx"`
	PolicyID      string `json:"policy_id"`
	AgentPolicyID string `json:"agent_policy_id"`
}

func (s *Scaffold) GetAgent(ctx context.Context, id string) ESAgentDoc {
	// NOTE we use ES instead of Kibana here as Kibana does not support agent_policy_id yet
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost:9200/.fleet-agents/_doc/"+id, nil)
	s.Require().NoError(err)
	req.SetBasicAuth(s.ElasticUser, s.ElasticPass)

	resp, err := s.Client.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)
	var obj struct {
		Source ESAgentDoc `json:"_source"`
	}
	err = json.NewDecoder(resp.Body).Decode(&obj)
	s.Require().NoError(err)
	return obj.Source
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

func (s *Scaffold) UpgradeAgent(ctx context.Context, id, version string) {
	body := strings.NewReader(fmt.Sprintf(`{"version": "%s", "force": true}`, version))
	req, err := http.NewRequestWithContext(ctx, "POST", "http://localhost:5601/api/fleet/agents/"+id+"/upgrade", body)
	s.Require().NoError(err)
	req.SetBasicAuth(s.ElasticUser, s.ElasticPass)
	req.Header.Set("kbn-xsrf", "e2e-setup")
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.Client.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)
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

type logger struct {
	*testing.T
}

func (l *logger) Printf(format string, v ...interface{}) {
	l.Helper()
	l.Logf(format, v...)
}

func (s *Scaffold) StartToxiproxy(ctx context.Context) *toxitc.Container {
	container, err := toxitc.Run(ctx, "ghcr.io/shopify/toxiproxy:2.12.0",
		testcontainers.WithLogger(&logger{s.T()}),
		testcontainers.CustomizeRequest(testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Hostname: "toxi",
				// Network is set to the integration test network instead of using host mode so it can easily communicate with other containers.
				// NOTE: the container will not become healthy when using `testcontainers-go 0.36.x+ if set to NetworkMode: "host"
				Networks: []string{"integration_default"},
			}}),
		toxitc.WithProxy("es", "elasticsearch:9200"),
	)
	if err != nil {
		s.T().Logf("Toxiproxy container creation failed, will retry: %v", err)
		container, err = toxitc.Run(ctx, "ghcr.io/shopify/toxiproxy:2.12.0",
			testcontainers.WithLogger(&logger{s.T()}),
			testcontainers.CustomizeRequest(testcontainers.GenericContainerRequest{
				ContainerRequest: testcontainers.ContainerRequest{
					Hostname: "toxi",
					// Network is set to the integration test network instead of using host mode so it can easily communicate with other containers.
					// NOTE: the container will not become healthy when using `testcontainers-go 0.36.x+ if set to NetworkMode: "host"
					Networks: []string{"integration_default"},
				}}),
			toxitc.WithProxy("es", "elasticsearch:9200"),
		)
	}
	s.Require().NoError(err)

	s.T().Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute) // use context.Background instead of s.T().Context() because this is a cleanup task
		defer cancel()
		if s.T().Failed() {
			rc, err := container.Logs(ctx)
			if err != nil {
				s.T().Logf("unable to get proxy container logs: %v", err)
			} else {
				p, err := io.ReadAll(rc)
				s.T().Logf("failed test log read err: %v, proxy container logs:\n%s", err, string(p))
				rc.Close()
			}
		}
		err := container.Terminate(ctx)
		if err != nil {
			s.T().Log("could not terminate toxiproxy container")
		}
	})

	return container
}

// HasTestStatusTrace will search elasticsearch for an APM trace to GET /api/status with labels.testName: name
// If a retry func is specified, it will be ran if the query for traces recieves no hits, the retry func is intended to generate a trace.
func (s *Scaffold) HasTestStatusTrace(ctx context.Context, name string, retry func(ctx context.Context)) {
	timer := time.NewTimer(time.Second)
	for {
		buf := bytes.NewBufferString(fmt.Sprintf(`{"query": {"bool": {"filter": [{"term": { "transaction.name": "GET /api/status"}}, {"term": { "labels.testName": "%s"}}]}}}`, name))
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost:9200/traces-apm-default/_search", buf)
		s.Require().NoError(err)
		req.SetBasicAuth(s.ElasticUser, s.ElasticPass)
		req.Header.Set("Content-Type", "application/json")

		select {
		case <-ctx.Done():
			s.Require().NoError(ctx.Err(), "context expired before status trace was detected")
			return
		case <-timer.C:
			resp, err := s.Client.Do(req)
			s.Require().NoError(err)
			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				timer.Reset(time.Second)
				continue
			}

			var obj struct {
				Hits struct {
					Total struct {
						Value int `json:"value"`
					} `json:"total"`
				} `json:"hits"`
			}
			err = json.NewDecoder(resp.Body).Decode(&obj)
			resp.Body.Close()
			s.Require().NoError(err)
			if obj.Hits.Total.Value > 0 {
				return
			}
			if retry != nil {
				retry(ctx)
			}
			timer.Reset(time.Second)
		}
	}
}

func (s *Scaffold) AddPolicyOverrides(ctx context.Context, id string, overrides map[string]interface{}) {
	body := struct {
		Name      string                 `json:"name"`
		Namespace string                 `json:"namespace"`
		Overrides map[string]interface{} `json:"overrides"`
	}{
		Name:      id,
		Namespace: "default",
		Overrides: overrides,
	}
	p, err := json.Marshal(&body)
	s.Require().NoError(err)
	s.UpdatePolicy(ctx, id, p)
}

func (s *Scaffold) UpdatePolicy(ctx context.Context, id string, body []byte) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, fmt.Sprintf("http://localhost:5601/api/fleet/agent_policies/%s", id), bytes.NewReader(body))
	s.Require().NoError(err)
	req.SetBasicAuth(s.ElasticUser, s.ElasticPass)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("kbn-xsrf", "e2e-test")
	resp, err := s.Client.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)
}

func (s *Scaffold) GetPolicy(ctx context.Context, id string) []byte {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://localhost:5601/api/fleet/agent_policies/%s", id), nil)
	s.Require().NoError(err)
	req.SetBasicAuth(s.ElasticUser, s.ElasticPass)
	req.Header.Set("kbn-xsrf", "e2e-test")
	resp, err := s.Client.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Require().Equal(http.StatusOK, resp.StatusCode)
	p, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)
	return p
}
