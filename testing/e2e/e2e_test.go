// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build e2e

package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/stretchr/testify/suite"
)

// BaseE2ETestSuite contains attributes and methods that are applicable to multiple test cases
type BaseE2ETestSuite struct {
	suite.Suite

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

	// find certs
	path, err := filepath.Abs(filepath.Join("..", "..", "build", "e2e-certs"))
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
			resp.Body.Close()

			// on success
			if resp.StatusCode == http.StatusOK {
				return
			}
			// fail, try after a wait
			timer.Reset(time.Second)
		}
	}
}
