// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build cloude2e

package cloude2e

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type TestSuite struct {
	suite.Suite

	fleetServerURL string // Fleet server URL

	client *http.Client // http.Client
}

type StatusResp struct {
	Status string `json:"status"`
}

func (suite *TestSuite) SetupSuite() {
	suite.T().Helper()

	// get env vars
	v, ok := os.LookupEnv("FLEET_SERVER_URL")
	suite.Require().True(ok, "expected FLEET_SERVER_URL to be defined")
	suite.fleetServerURL = v

	suite.client = &http.Client{}
}

func TestBaseE2ETestSuite(t *testing.T) {
	suite.Run(t, new(TestSuite))
}

// FleetServerStatusOK will poll fleet-server's status endpoint every second and return when it responds with a 200 status code
// if the passed context terminates before a 200 is returned the current test will be marked as failed.
func (suite *TestSuite) TestFleetServerStatusOK() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// ping /api/status
	req, err := http.NewRequestWithContext(ctx, "GET", suite.fleetServerURL+"/api/status", nil)
	suite.Require().NoError(err)

	resp, err := suite.client.Do(req)
	suite.Require().NoError(err)
	suite.Require().Equal(http.StatusOK, resp.StatusCode)

	var body StatusResp
	err = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	suite.Require().NoError(err)
	suite.Require().Equal("HEALTHY", body.Status)

}
