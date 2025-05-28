// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build cloude2e

package cloude2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/suite"

	"github.com/elastic/elastic-agent-libs/kibana"

	"github.com/elastic/fleet-server/pkg/api"
	"github.com/elastic/fleet-server/v7/version"
)

type TestSuite struct {
	suite.Suite

	fleetServerURL string
	kibanaURL      string
	username       string
	password       string

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

	v, ok = os.LookupEnv("KIBANA_URL")
	suite.Require().True(ok, "expected KIBANA_URL to be defined")
	suite.kibanaURL = v

	v, ok = os.LookupEnv("ELASTIC_USER")
	suite.Require().True(ok, "expected ELASTIC_USER to be defined")
	suite.username = v

	v, ok = os.LookupEnv("ELASTIC_PASS")
	suite.Require().True(ok, "expected ELASTIC_PASS to be defined")
	suite.password = v

	suite.client = &http.Client{}
}

func TestBaseE2ETestSuite(t *testing.T) {
	suite.Run(t, new(TestSuite))
}

// TestFleetServerStatusOK will poll fleet-server's status endpoint every second and return when it responds with a 200 status code
// if the passed context terminates before a 200 is returned the current test will be marked as failed.
func (suite *TestSuite) TestFleetServerStatusOK() {
	ctx, cancel := context.WithTimeout(suite.T().Context(), time.Minute)
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

// TestFleetServerSmoke will use the fleet-server api to enroll an agent, make a checkin, and ack the POLICY_CHANGE action.
func (suite *TestSuite) TestFleetServerSmoke() {
	suite.T().Log("Creating test policy...")
	kClient, err := kibana.NewClientWithConfigDefault(&kibana.ClientConfig{
		Host:          suite.kibanaURL,
		Username:      suite.username,
		Password:      suite.password,
		IgnoreVersion: false,
	}, 443, "fleet-server-cloude2e", version.DefaultVersion, "", time.Now().UTC().Format(time.RFC3339))
	suite.Require().NoError(err, "unable to create Kibana client")

	policySuffix := uuid.Must(uuid.NewV4()).String()
	policy, err := kClient.CreatePolicy(suite.T().Context(), kibana.AgentPolicy{
		Name:        "fleet-server-cloud-test" + policySuffix,
		Namespace:   "default",
		Description: "Test polciy " + policySuffix,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	})
	suite.Require().NoError(err)

	suite.T().Logf("Creating enrollment token for policy %s...", policy.ID)
	enrollmentToken, err := kClient.CreateEnrollmentAPIKey(suite.T().Context(), kibana.CreateEnrollmentAPIKeyRequest{
		PolicyID: policy.ID,
	})
	suite.Require().NoError(err)

	suite.T().Logf("Enrolling an agent into policy %s...", policy.ID)
	fClient, err := api.NewClientWithResponses(suite.fleetServerURL)
	suite.Require().NoError(err, "unable to create fleet-server client")

	enrollResp, err := fClient.AgentEnrollWithResponse(suite.T().Context(),
		&api.AgentEnrollParams{UserAgent: "elastic agent " + version.DefaultVersion},
		api.AgentEnrollJSONRequestBody{
			Type: api.PERMANENT,
			Metadata: api.EnrollMetadata{
				Local: json.RawMessage(fmt.Sprintf(`{"elastic":{"agent":{"version":"%s"}}}`, version.DefaultVersion)),
			},
		},
		func(ctx context.Context, r *http.Request) error {
			r.Header.Set("Authorization", "ApiKey "+enrollmentToken.APIKey)
			return nil
		},
	)
	suite.Require().NoError(err)
	suite.Require().Equal(http.StatusOK, enrollResp.StatusCode())
	enroll := enrollResp.JSON200
	suite.Require().NotEmpty(enroll.Item.Id, "expected agent ID in response")
	suite.Require().NotEmpty(enroll.Item.AccessApiKey, "expected agent API key in response")

	suite.T().Logf("Agent %s checking in...", enroll.Item.Id)
	checkinResp, err := fClient.AgentCheckinWithResponse(suite.T().Context(), enroll.Item.Id,
		&api.AgentCheckinParams{UserAgent: "elastic agent " + version.DefaultVersion},
		api.AgentCheckinJSONRequestBody{
			Status:  api.CheckinRequestStatusOnline,
			Message: "test checkin",
		},
		func(ctx context.Context, r *http.Request) error {
			r.Header.Set("Authorization", "ApiKey "+enroll.Item.AccessApiKey)
			return nil
		},
	)
	suite.Require().NoError(err)
	suite.Require().Equal(http.StatusOK, checkinResp.StatusCode())
	checkin := checkinResp.JSON200
	suite.Require().NotNil(checkin.AckToken, "expected to recieve ack token from checkin")
	suite.Require().NotNil(checkin.Actions, "expected to actions from checkin")

	events := make([]api.AckRequest_Events_Item, 0, len(*checkin.Actions))
	for _, action := range *checkin.Actions {
		event := api.AckRequest_Events_Item{}
		err = event.FromGenericEvent(api.GenericEvent{
			ActionId: action.Id,
			AgentId:  enroll.Item.Id,
		})
		suite.Require().NoError(err)
		events = append(events, event)
	}

	suite.T().Logf("Agent %s acking actions...", enroll.Item.Id)
	ackResp, err := fClient.AgentAcksWithResponse(suite.T().Context(), enroll.Item.Id,
		&api.AgentAcksParams{},
		api.AgentAcksJSONRequestBody{
			Events: events,
		},
		func(ctx context.Context, r *http.Request) error {
			r.Header.Set("Authorization", "ApiKey "+enroll.Item.AccessApiKey)
			return nil
		},
	)
	suite.Require().NoError(err)
	suite.Require().Equal(http.StatusOK, ackResp.StatusCode())
	acks := ackResp.JSON200
	suite.Require().False(acks.Errors, "ack response indicated an error")
}
