// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.
// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package api_version

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/pkg/api"
	"github.com/elastic/fleet-server/testing/e2e/scaffold"
	"github.com/elastic/fleet-server/v7/version"
)

// ClientAPITester provides methods to test API endpoints
type ClientAPITester struct {
	*scaffold.Scaffold

	endpoint      string
	enrollmentKey string
}

func NewClientAPITesterCurrent(scaffold scaffold.Scaffold, endpoint, enrollmentKey string) *ClientAPITester {
	return &ClientAPITester{
		&scaffold,
		endpoint,
		enrollmentKey,
	}
}

func (tester *ClientAPITester) SetEndpoint(endpoint string) {
	tester.endpoint = endpoint
}

func (tester *ClientAPITester) SetKey(key string) {
	tester.enrollmentKey = key
}

// Status tests the status endpoint, if an apiKey is given the authenticated response if verfied.
func (tester *ClientAPITester) Status(ctx context.Context, apiKey string) {
	client, err := api.NewClientWithResponses(tester.endpoint, api.WithHTTPClient(tester.Client))
	tester.Require().NoError(err)

	var resp *api.StatusResponse
	if apiKey != "" {
		resp, err = client.StatusWithResponse(ctx, &api.StatusParams{}, func(ctx context.Context, req *http.Request) error {
			req.Header.Set("Authorization", "ApiKey "+apiKey)
			return nil
		})
	} else {
		resp, err = client.StatusWithResponse(ctx, &api.StatusParams{})
	}
	tester.Require().NoError(err)
	tester.Require().Equal(http.StatusOK, resp.StatusCode())
	tester.Require().NotEmpty(resp.JSON200.Name)
	tester.Require().NotEmpty(resp.JSON200.Status)
	if apiKey != "" {
		tester.Require().NotNil(resp.JSON200.Version)
	}
}

// Enroll tests the enroll endpoint with the given apiKey.
// Returns the agentID and agentAPIKey.
func (tester *ClientAPITester) Enroll(ctx context.Context, apiKey string) (string, string) {
	client, err := api.NewClientWithResponses(tester.endpoint, api.WithHTTPClient(tester.Client), api.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "ApiKey "+apiKey)
		return nil
	}))
	tester.Require().NoError(err)

	enrollResp, err := client.AgentEnrollWithResponse(ctx,
		&api.AgentEnrollParams{UserAgent: "elastic agent " + version.DefaultVersion},
		api.AgentEnrollJSONRequestBody{
			Metadata: api.EnrollMetadata{
				Local: json.RawMessage(fmt.Sprintf(enrollMetadataTpl, version.DefaultVersion)),
			},
			Type: api.PERMANENT,
		},
	)
	tester.Require().NoError(err)
	tester.Require().Equal(http.StatusOK, enrollResp.StatusCode())

	enroll := enrollResp.JSON200
	tester.Require().NotEmpty(enroll.Item.Id, "expected agent ID in response")
	tester.Require().NotEmpty(enroll.Item.AccessApiKey, "expected agent API key in response")
	return enroll.Item.Id, enroll.Item.AccessApiKey
}

// Checkin tests the checkin endpoint.
// Returns the new ack token and the list of actions.
func (tester *ClientAPITester) Checkin(ctx context.Context, apiKey, agentID string, ackToken, dur *string, requestBody *api.AgentCheckinJSONRequestBody) (*string, []string, int) {
	client, err := api.NewClientWithResponses(tester.endpoint, api.WithHTTPClient(tester.Client), api.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "ApiKey "+apiKey)
		return nil
	}))
	tester.Require().NoError(err)

	if requestBody == nil {
		requestBody = &api.AgentCheckinJSONRequestBody{
			Status:      api.CheckinRequestStatusOnline,
			Message:     "test checkin",
			PollTimeout: dur,
		}
	}
	requestBody.AckToken = ackToken
	if dur != nil {
		requestBody.PollTimeout = dur
	}

	resp, err := client.AgentCheckinWithResponse(ctx, agentID, &api.AgentCheckinParams{UserAgent: "elastic agent " + version.DefaultVersion}, *requestBody)
	tester.Require().NoError(err)

	// No need to process the response further if we're testing for a bad request;
	// just return the status code
	// For valid requests, process as usual
	if resp.StatusCode() != http.StatusOK {
		var respErr *api.Error
		switch {
		case resp.JSON400 != nil:
			respErr = resp.JSON400
		case resp.JSON401 != nil:
			respErr = resp.JSON401
		case resp.JSON403 != nil:
			respErr = resp.JSON403
		case resp.JSON404 != nil:
			respErr = resp.JSON404
		case resp.JSON408 != nil:
			respErr = resp.JSON408
		case resp.JSON500 != nil:
			respErr = resp.JSON500
		case resp.JSON503 != nil:
			respErr = resp.JSON503
		}
		tester.T().Logf("Response error detected: %+v", respErr)
		return nil, nil, resp.StatusCode()
	}

	// Process a successful check-in response.
	checkin := resp.JSON200
	tester.Require().NotNil(checkin.AckToken, "expected to recieve ack token from checkin")

	actionIds := make([]string, len(checkin.Actions))
	for i, action := range checkin.Actions {
		actionIds[i] = action.Id
	}

	return checkin.AckToken, actionIds, resp.StatusCode()
}

// Acks tests the acks endpoint
func (tester *ClientAPITester) Acks(ctx context.Context, apiKey, agentID string, actionsIDs []string) {
	client, err := api.NewClientWithResponses(tester.endpoint, api.WithHTTPClient(tester.Client), api.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "ApiKey "+apiKey)
		return nil
	}))
	tester.Require().NoError(err)

	events := make([]api.AckRequest_Events_Item, 0, len(actionsIDs))
	for _, actionId := range actionsIDs {
		event := api.AckRequest_Events_Item{}
		err := event.FromGenericEvent(api.GenericEvent{
			ActionId: actionId,
			AgentId:  agentID,
		})
		tester.Require().NoError(err)
		events = append(events, event)
	}

	resp, err := client.AgentAcksWithResponse(ctx,
		agentID,
		&api.AgentAcksParams{},
		api.AgentAcksJSONRequestBody{
			Events: events,
		},
	)
	tester.Require().NoError(err)
	tester.Require().Equal(http.StatusOK, resp.StatusCode())

	acks := resp.JSON200
	tester.Require().Falsef(acks.Errors, "error in acked items: %v", acks.Items)
}

// FullFileUpload tests the file upload endpoints (begin, chunk, complete).
func (tester *ClientAPITester) FullFileUpload(ctx context.Context, apiKey, agentID, actionID string, size int64) {
	client, err := api.NewClientWithResponses(tester.endpoint, api.WithHTTPClient(tester.Client), api.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "ApiKey "+apiKey)
		return nil
	}))
	tester.Require().NoError(err)

	beginResp, err := client.UploadBeginWithResponse(ctx,
		&api.UploadBeginParams{},
		api.UploadBeginJSONRequestBody{
			ActionId: actionID,
			AgentId:  agentID,
			File: api.UploadBeginRequest_File{
				Name:     "test-file.zip",
				MimeType: "application/zip",
				Size:     size,
			},
			Src: api.Agent,
		},
	)
	tester.Require().NoError(err)
	tester.Require().Equal(http.StatusOK, beginResp.StatusCode())
	tester.Require().NotEmpty(beginResp.JSON200.UploadId)
	tester.Require().NotZero(beginResp.JSON200.ChunkSize)
	uploadID := beginResp.JSON200.UploadId
	chunkSize := beginResp.JSON200.ChunkSize

	chunkCount := int(math.Ceil(float64(size) / float64(chunkSize)))
	tHash := sha256.New()
	for i := 0; i < chunkCount; i++ {
		var body bytes.Buffer
		n := int64(math.Min(float64(chunkSize), float64(size)))
		size = size - n
		_, err := io.CopyN(&body, rand.Reader, n)
		tester.Require().NoError(err)
		hash := sha256.Sum256(body.Bytes())
		chunkResp, err := client.UploadChunkWithBodyWithResponse(ctx,
			uploadID,
			i,
			&api.UploadChunkParams{XChunkSHA2: fmt.Sprintf("%x", hash[:])},
			"application/octet-stream",
			&body,
		)
		tester.Require().NoError(err)
		tester.Require().Equal(http.StatusOK, chunkResp.StatusCode())
		tHash.Write(hash[:])
	}

	completeResp, err := client.UploadCompleteWithResponse(ctx,
		uploadID,
		&api.UploadCompleteParams{},
		api.UploadCompleteJSONRequestBody{
			Transithash: struct {
				Sha256 string `json:"sha256"`
			}{
				Sha256: fmt.Sprintf("%x", tHash.Sum(nil)),
			},
		},
	)
	tester.Require().NoError(err)
	tester.Require().Equal(http.StatusOK, completeResp.StatusCode())
}

// Artifact tests the artifact endpoint with the passed id and sha2 values.
// The hash of the retrieved body is expected to be equal to encodedSHA
func (tester *ClientAPITester) Artifact(ctx context.Context, apiKey, id, sha2, encodedSHA string) {
	client, err := api.NewClientWithResponses(tester.endpoint, api.WithHTTPClient(tester.Client), api.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "ApiKey "+apiKey)
		return nil
	}))
	tester.Require().NoError(err)

	resp, err := client.ArtifactWithResponse(ctx,
		id,
		sha2,
		&api.ArtifactParams{},
	)
	tester.Require().NoError(err)
	tester.Require().Equal(http.StatusOK, resp.StatusCode())
	hash := sha256.Sum256(resp.Body)
	tester.Require().Equal(encodedSHA, fmt.Sprintf("%x", hash[:]))
}

func (tester *ClientAPITester) GetPGPKey(ctx context.Context) []byte {
	client, err := api.NewClientWithResponses(tester.endpoint, api.WithHTTPClient(tester.Client))
	tester.Require().NoError(err)

	resp, err := client.GetPGPKeyWithResponse(ctx, 1, 2, 3, nil)
	tester.Require().NoError(err)
	if strings.HasPrefix(tester.endpoint, "https") {
		tester.Require().Equal(http.StatusOK, resp.StatusCode())
	} else {
		tester.Require().Equal(http.StatusNotImplemented, resp.StatusCode())
	}
	return resp.Body
}

func (tester *ClientAPITester) AuditUnenroll(ctx context.Context, apiKey, id string, reason api.AuditUnenrollRequestReason, timestamp time.Time) int {
	client, err := api.NewClientWithResponses(tester.endpoint, api.WithHTTPClient(tester.Client), api.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "ApiKey "+apiKey)
		return nil
	}))
	tester.Require().NoError(err)

	resp, err := client.AuditUnenrollWithResponse(ctx, id, nil, api.AuditUnenrollJSONRequestBody{Reason: reason, Timestamp: timestamp})
	tester.Require().NoError(err)
	return resp.StatusCode()
}

func (tester *ClientAPITester) TestStatus_Unauthenticated() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tester.Status(ctx, "")
}

func (tester *ClientAPITester) TestStatus_Authenticated() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tester.Status(ctx, tester.enrollmentKey)
}

func (tester *ClientAPITester) TestEnrollCheckinAck() {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	tester.T().Log("test enrollment")
	agentID, agentKey := tester.Enroll(ctx, tester.enrollmentKey)
	tester.VerifyAgentInKibana(ctx, agentID)

	tester.T().Logf("test checkin 1: agent %s", agentID)
	ackToken, actions, statusCode := tester.Checkin(ctx, agentKey, agentID, nil, nil, nil)
	tester.Require().Equal(http.StatusOK, statusCode, "Expected status code 200 for successful checkin")
	tester.Require().NotEmpty(actions)

	tester.T().Log("test ack")
	tester.Acks(ctx, agentKey, agentID, actions)

	tester.T().Logf("test checkin 2: agent %s 3m timout", agentID)
	dur := "3m"

	_, _, newStatusCode := tester.Checkin(ctx, agentKey, agentID, ackToken, &dur, nil)
	tester.Require().Equal(http.StatusOK, newStatusCode, "Expected status code 200 for successful checkin with timeout")

	// sanity check agent status in kibana
	tester.AgentIsOnline(ctx, agentID)
}

func (tester *ClientAPITester) TestCheckinWithBadRequest() {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	tester.T().Log("test enrollment")
	agentID, agentKey := tester.Enroll(ctx, tester.enrollmentKey)
	tester.VerifyAgentInKibana(ctx, agentID)

	tester.T().Logf("test checkin 1: agent %s", agentID)

	_, _, statusCode := tester.Checkin(ctx, agentKey, agentID, nil, nil, &api.CheckinRequest{})
	tester.Require().Equal(http.StatusBadRequest, statusCode, "Expected status code 400 for bad request")
}

func (tester *ClientAPITester) TestCheckinWithActionNotFound() {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	// enroll agent
	tester.T().Log("test enrollment")
	agentID, agentKey := tester.Enroll(ctx, tester.enrollmentKey)
	tester.VerifyAgentInKibana(ctx, agentID)

	tester.T().Logf("test checkin with no upgrade action: agent %s", agentID)
	// checkin request with upgrade details
	req := &api.AgentCheckinJSONRequestBody{
		Status:  api.CheckinRequestStatusOnline,
		Message: "test checkin",
		UpgradeDetails: &api.UpgradeDetails{
			ActionId: "test-missing-id",
			State:    api.UpgradeDetailsStateUPGDOWNLOADING,
		},
	}
	_, _, statusCode := tester.Checkin(ctx, agentKey, agentID, nil, nil, req)
	tester.Require().Equal(http.StatusOK, statusCode, "Expected status code 200 for successful checkin with action not found")
}

func (tester *ClientAPITester) TestFullFileUpload() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agentID, agentKey := tester.Enroll(ctx, tester.enrollmentKey)
	actionID := tester.RequestDiagnosticsForAgent(ctx, agentID)

	tester.FullFileUpload(ctx, agentKey, agentID, actionID, 8192) // 8KiB file
}

func (tester *ClientAPITester) TestArtifact() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	_, agentKey := tester.Enroll(ctx, tester.enrollmentKey)
	tester.AddSecurityContainer(ctx)
	tester.AddSecurityContainerItem(ctx)

	hits := tester.FleetHasArtifacts(ctx)
	tester.Artifact(ctx, agentKey, hits[0].Source.Identifier, hits[0].Source.DecodedSHA256, hits[0].Source.EncodedSHA256)
}

func (tester *ClientAPITester) TestGetPGPKey() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tester.GetPGPKey(ctx)
}

func (tester *ClientAPITester) TestEnrollAuditUnenroll() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	now := time.Now().UTC()

	tester.T().Log("test enrollment")
	agentID, agentKey := tester.Enroll(ctx, tester.enrollmentKey)
	tester.VerifyAgentInKibana(ctx, agentID)

	tester.T().Logf("use audit/unenroll endpoint for agent: %s", agentID)
	status := tester.AuditUnenroll(ctx, agentKey, agentID, api.Uninstall, now)
	tester.Require().Equal(http.StatusOK, status)

	tester.T().Logf("use audit/unenroll endpoint to replace uninstalled with orphaned for agent: %s", agentID)
	status = tester.AuditUnenroll(ctx, agentKey, agentID, api.Orphaned, now)
	tester.Require().Equal(http.StatusOK, status)

	tester.T().Logf("audit/unenroll endpoint for agent: %s should return conflict", agentID)
	status = tester.AuditUnenroll(ctx, agentKey, agentID, api.Uninstall, now)
	tester.Require().Equal(http.StatusConflict, status)

	tester.T().Logf("test checkin agent: %s", agentID)
	_, _, statusCode := tester.Checkin(ctx, agentKey, agentID, nil, nil, nil)
	tester.Require().Equal(http.StatusOK, statusCode, "Expected status code 200 for successful checkin")

	// verify that audit_unenrolled_reason attribute does not exist in agent doc
	tester.Require().Eventually(func() bool {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+tester.ESHosts+"/.fleet-agents/_doc/"+agentID, nil)
		tester.Require().NoError(err)
		req.SetBasicAuth(tester.ElasticUser, tester.ElasticPass)
		res, err := tester.Client.Do(req)
		tester.Require().NoError(err)
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return false
		}
		var obj struct {
			Source map[string]interface{} `json:"_source"`
		}
		err = json.NewDecoder(res.Body).Decode(&obj)
		tester.Require().NoError(err)
		_, ok := obj.Source["audit_unenrolled_reason"]
		return !ok
	}, time.Second*20, time.Second, "agent document in elasticsearch should not have audit_unenrolled_reason attribute")
}

// TestEnrollUpgradeAction_MetadataDownloadRate_String checks that download metadata rates can be sent as strings
// Prevents: https://github.com/elastic/fleet-server/issues/5164
func (tester *ClientAPITester) TestEnrollUpgradeAction_MetadataDownloadRate_String() {
	ctx, cancel := context.WithCancel(tester.T().Context())
	defer cancel()

	tester.T().Log("enroll agent")
	agentID, agentKey := tester.Enroll(ctx, tester.enrollmentKey)
	tester.VerifyAgentInKibana(ctx, agentID)

	tester.T().Logf("test checkin 1: agent %s", agentID)
	ackToken, actions, statusCode := tester.Checkin(ctx, agentKey, agentID, nil, nil, nil)
	tester.Require().Equal(http.StatusOK, statusCode, "Expected status code 200 for successful checkin")
	tester.Require().NotEmpty(actions)

	tester.T().Log("test ack")
	tester.Acks(ctx, agentKey, agentID, actions)

	tester.T().Logf("Request upgrade for agent: %s", agentID)
	tester.UpgradeAgent(ctx, agentID, "9.0.0")

	tester.T().Logf("test checkin 2: agent %s", agentID)
	checkin2Ctx, checkin2Cancel := context.WithTimeout(ctx, time.Second*15) // use a short checking here - the action should be immediatly returned
	defer checkin2Cancel()
	ackToken, actions, statusCode = tester.Checkin(checkin2Ctx, agentKey, agentID, ackToken, nil, nil)
	tester.Require().Equal(http.StatusOK, statusCode, "Expected status code 200 for successful checkin")
	tester.Require().NotEmpty(actions)

	// Checkin with a request body that has a string download rate
	dur := "1m" // 1m is min pollDuration value
	body := &api.AgentCheckinJSONRequestBody{
		Status:      api.CheckinRequestStatusOnline,
		Message:     "test checkin",
		PollTimeout: &dur,
		UpgradeDetails: &api.UpgradeDetails{
			ActionId:      actions[0], // Assume action 0 is upgrade
			State:         api.UpgradeDetailsStateUPGDOWNLOADING,
			TargetVersion: "9.0.0", // FIXME
			Metadata:      &api.UpgradeDetails_Metadata{},
		},
	}
	err := body.UpgradeDetails.Metadata.UnmarshalJSON([]byte(`{"download_percent": 10,"download_rate": "10kbps"}`))
	tester.Require().NoError(err)

	tester.T().Logf("test checkin 3: agent %s", agentID)
	_, _, statusCode = tester.Checkin(ctx, agentKey, agentID, ackToken, &dur, body)
	tester.Require().Equal(http.StatusOK, statusCode, "Expected status code 200 for successful checkin")
}

func (tester *ClientAPITester) TestCheckinWithPolicyIDRevision() {
	ctx, cancel := context.WithTimeout(tester.T().Context(), 4*time.Minute)
	defer cancel()
	dur := "60s" // 60s is the min poll duraton fleet-server allows

	tester.T().Log("Enroll an agent")
	agentID, agentKey := tester.Enroll(ctx, tester.enrollmentKey)
	tester.VerifyAgentInKibana(ctx, agentID)

	client, err := api.NewClientWithResponses(tester.endpoint, api.WithHTTPClient(tester.Client), api.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "ApiKey "+agentKey)
		return nil
	}))
	tester.Require().NoError(err)

	tester.T().Logf("test checkin 1: retrieve POLICY_CHANGE action for agent %s", agentID)
	resp, err := client.AgentCheckinWithResponse(ctx, agentID, &api.AgentCheckinParams{UserAgent: "elastic agent " + version.DefaultVersion}, api.AgentCheckinJSONRequestBody{
		Status:  api.CheckinRequestStatusOnline,
		Message: "test checkin",
	})
	tester.Require().NoError(err)
	tester.Require().Equal(http.StatusOK, resp.StatusCode())

	checkin := resp.JSON200
	tester.Require().NotEmpty(checkin.Actions)
	var policyChange api.ActionPolicyChange
	found := false
	for _, action := range checkin.Actions {
		if action.Type == api.POLICYCHANGE {
			policyChange, err = action.Data.AsActionPolicyChange()
			tester.Require().NoError(err)
			found = true
			break
		}
	}
	tester.Require().True(found, "unable to find POLICY_CHANGE action in 1st checkin response")
	policyID := policyChange.Policy.Id
	revIDX := int64(policyChange.Policy.Revision) // TODO change mapping in openapi?

	// Checkin with policyID revIDX
	// No actions should be returned
	// Manage any API keys if present
	tester.T().Logf("test checkin 2: agent %s with policy %s:%d in request body", agentID, policyID, revIDX)
	resp, err = client.AgentCheckinWithResponse(ctx, agentID, &api.AgentCheckinParams{UserAgent: "elastic agent " + version.DefaultVersion}, api.AgentCheckinJSONRequestBody{
		Status:            api.CheckinRequestStatusOnline,
		Message:           "test checkin",
		PollTimeout:       &dur,
		AgentPolicyId:     &policyID,
		PolicyRevisionIdx: &revIDX,
	})
	tester.Require().NoError(err)
	tester.Require().Equal(http.StatusOK, resp.StatusCode())
	checkin = resp.JSON200
	tester.Require().Empty(checkin.Actions, "Unexpected action in response")

	tester.Require().EventuallyWithT(func(c *assert.CollectT) {
		agent := tester.GetAgent(ctx, agentID)
		assert.Equal(c, policyID, agent.AgentPolicyID)
		assert.Equal(c, revIDX, int64(agent.Revision))
	}, time.Second*20, time.Second)

	// Check in with revIDX that does not exist
	// POLICY_CHANGE should be returned
	// No API keys changed
	// agent doc will be updated with sent values
	newRevIDX := revIDX + 1
	tester.T().Logf("test checkin 3: agent %s with revision_idx+1 %d (fast forward)", agentID, newRevIDX)
	resp, err = client.AgentCheckinWithResponse(ctx, agentID, &api.AgentCheckinParams{UserAgent: "elastic agent " + version.DefaultVersion}, api.AgentCheckinJSONRequestBody{
		Status:            api.CheckinRequestStatusOnline,
		Message:           "test checkin",
		PollTimeout:       &dur,
		AgentPolicyId:     &policyID,
		PolicyRevisionIdx: &newRevIDX,
	})
	tester.Require().NoError(err)
	tester.Require().Equal(http.StatusOK, resp.StatusCode())

	checkin = resp.JSON200
	found = false
	for _, action := range checkin.Actions {
		if action.Type == api.POLICYCHANGE {
			policyChange, err = action.Data.AsActionPolicyChange()
			tester.Require().NoError(err)
			found = true
			break
		}
	}
	tester.Require().True(found, "unable to find POLICY_CHANGE action in 3rd checkin response")
	tester.Require().Equal(policyID, policyChange.Policy.Id)
	tester.Require().Equal(revIDX, int64(policyChange.Policy.Revision))

	tester.Require().EventuallyWithT(func(c *assert.CollectT) {
		agent := tester.GetAgent(ctx, agentID)
		assert.Equal(c, policyID, agent.AgentPolicyID)
		assert.Equal(c, newRevIDX, int64(agent.Revision))
	}, time.Second*20, time.Second)

	// Update policy
	// Get the policy then "update" it without changing anything - revision ID should increment
	tester.T().Logf("Update policy %s", policyID)
	rawPolicy := tester.GetPolicy(ctx, policyID)
	var obj map[string]any
	err = json.Unmarshal(rawPolicy, &obj)
	tester.Require().NoError(err)
	item, ok := obj["item"]
	tester.Require().True(ok, "Expected item in object: %v", obj)
	obj, ok = item.(map[string]any)
	tester.Require().True(ok, "Expected item to be object: %T", item)
	reqObj := make(map[string]any)
	// Copy some attributes - name and namespace are required.
	for _, k := range []string{"name", "namespace", "id", "space_ids", "inactivity_timeout"} {
		reqObj[k] = obj[k]
	}
	rawPolicy, err = json.Marshal(reqObj)
	tester.Require().NoError(err)

	tester.UpdatePolicy(ctx, policyID, rawPolicy)
	rawPolicy = tester.GetPolicy(ctx, policyID)

	// Verify that the revision has incremented
	err = json.Unmarshal(rawPolicy, &obj)
	tester.Require().NoError(err)
	item, ok = obj["item"]
	tester.Require().True(ok, "Expected item in object: %v", obj)
	obj, ok = item.(map[string]any)
	tester.Require().True(ok, "Expected item to be object: %T", item)
	oRev, ok := obj["revision"]
	tester.Require().True(ok, "revision not found in: %v", obj)
	iRev, ok := oRev.(float64) // numbers will serialize to float64 by default
	tester.Require().True(ok, "revision is not a float64: %T", oRev)
	tester.Require().Equal(revIDX+1, int64(iRev), "Expected policy revision to be exactly one greater than last revision.")
	tester.T().Logf("Policy has been updated to revision %d.", int64(iRev))

	// Do a checkin with revIDX (policy.revision - 1)
	// Last checkin should have already recorded the agent as running policy_revision, but this checkin must return a POLICY_CHANGE action.
	// Note that API keys (if any) would be managed here
	tester.T().Logf("test checkin 4: agent %s with policy.revision-1 %d", agentID, revIDX)
	resp, err = client.AgentCheckinWithResponse(ctx, agentID, &api.AgentCheckinParams{UserAgent: "elastic agent " + version.DefaultVersion}, api.AgentCheckinJSONRequestBody{
		Status:            api.CheckinRequestStatusOnline,
		Message:           "test checkin",
		PollTimeout:       &dur,
		AgentPolicyId:     &policyID,
		PolicyRevisionIdx: &revIDX,
	})
	tester.Require().NoError(err)
	tester.Require().Equal(http.StatusOK, resp.StatusCode())
	checkin = resp.JSON200
	tester.Require().NotEmpty(checkin.Actions, "Expected an action in the response")
	found = false
	for _, action := range checkin.Actions {
		if action.Type == api.POLICYCHANGE {
			policyChange, err = action.Data.AsActionPolicyChange()
			tester.Require().NoError(err)
			found = true
			break
		}
	}
	tester.Require().True(found, "unable to find POLICY_CHANGE action in 4th checkin response")
	revIDX = int64(policyChange.Policy.Revision)
	tester.Require().Equal(int64(iRev), revIDX, "Expected POLICY_CHANGE action to be for updated policy revision")

	tester.Require().EventuallyWithT(func(c *assert.CollectT) {
		agent := tester.GetAgent(ctx, agentID)
		require.Equal(c, policyID, agent.AgentPolicyID)
		require.Equal(c, revIDX, int64(agent.Revision))
	}, time.Second*20, time.Second)

	// Do a normal checkin to "reset" to latest revision_idx
	// no actions are returned
	// Manage any API keys if present
	tester.T().Logf("test checkin 5: agent %s with policy %s:%d in request body", agentID, policyID, revIDX)
	resp, err = client.AgentCheckinWithResponse(ctx, agentID, &api.AgentCheckinParams{UserAgent: "elastic agent " + version.DefaultVersion}, api.AgentCheckinJSONRequestBody{
		Status:            api.CheckinRequestStatusOnline,
		Message:           "test checkin",
		PollTimeout:       &dur,
		AgentPolicyId:     &policyID,
		PolicyRevisionIdx: &revIDX,
	})
	tester.Require().NoError(err)
	tester.Require().Equal(http.StatusOK, resp.StatusCode())
	checkin = resp.JSON200
	tester.Require().Empty(checkin.Actions, "Unexpected action in response")

	tester.Require().EventuallyWithT(func(c *assert.CollectT) {
		agent := tester.GetAgent(ctx, agentID)
		require.Equal(c, policyID, agent.AgentPolicyID)
		require.Equal(c, revIDX, int64(agent.Revision))
	}, time.Second*20, time.Second)

	// Test that if the agent is "restored" to an earlier revIDX a policy_change is sent
	prevRev := revIDX - 1
	tester.T().Logf("test checkin 6: agent %s with policy %s:%d (rewind)", agentID, policyID, prevRev)
	resp, err = client.AgentCheckinWithResponse(ctx, agentID, &api.AgentCheckinParams{UserAgent: "elastic agent " + version.DefaultVersion}, api.AgentCheckinJSONRequestBody{
		Status:            api.CheckinRequestStatusOnline,
		Message:           "test checkin",
		PollTimeout:       &dur,
		AgentPolicyId:     &policyID,
		PolicyRevisionIdx: &prevRev,
	})
	tester.Require().NoError(err)
	tester.Require().Equal(http.StatusOK, resp.StatusCode())
	checkin = resp.JSON200
	tester.Require().NotEmpty(checkin.Actions, "Expected action in response")

	tester.Require().EventuallyWithT(func(c *assert.CollectT) {
		agent := tester.GetAgent(ctx, agentID)
		require.Equal(c, policyID, agent.AgentPolicyID)
		require.Equal(c, prevRev, int64(agent.Revision))
	}, time.Second*20, time.Second)

	// agent is now recorded as on a previous revision - check to make sure a checkin without AgentPolicyId and revision result in a POLICY_CHANGE action
	tester.T().Logf("test checkin 7: agent %s with no policy or revision", agentID)
	resp, err = client.AgentCheckinWithResponse(ctx, agentID, &api.AgentCheckinParams{UserAgent: "elastic agent " + version.DefaultVersion}, api.AgentCheckinJSONRequestBody{
		Status:      api.CheckinRequestStatusOnline,
		Message:     "test checkin",
		PollTimeout: &dur,
	})
	tester.Require().NoError(err)
	tester.Require().Equal(http.StatusOK, resp.StatusCode())
	checkin = resp.JSON200
	tester.Require().NotEmpty(checkin.Actions, "Expected action in response")
	actionID := ""
	for _, action := range checkin.Actions {
		if action.Type == api.POLICYCHANGE {
			actionID = action.Id
			break
		}
	}
	tester.Require().NotEmptyf(actionID, "expected to find POLICY_CHANGE action id in %+v", checkin.Actions)

	tester.T().Log("Ack the POLICY_CHANGE action")
	tester.Acks(ctx, agentKey, agentID, []string{actionID})

	tester.T().Logf("test checkin 8: agent %s with no policy or revision should not recieve action", agentID)
	resp, err = client.AgentCheckinWithResponse(ctx, agentID, &api.AgentCheckinParams{UserAgent: "elastic agent " + version.DefaultVersion}, api.AgentCheckinJSONRequestBody{
		Status:      api.CheckinRequestStatusOnline,
		Message:     "test checkin",
		PollTimeout: &dur,
	})
	tester.Require().NoError(err)
	tester.Require().Equal(http.StatusOK, resp.StatusCode())
	checkin = resp.JSON200
	tester.Require().Empty(checkin.Actions, "Unexpected action in response")

	tester.Require().EventuallyWithT(func(c *assert.CollectT) {
		agent := tester.GetAgent(ctx, agentID)
		assert.Equal(c, policyID, agent.AgentPolicyID)
		assert.Equal(c, revIDX, int64(agent.Revision))
	}, time.Second*20, time.Second)

	// sanity check agent status in kibana
	tester.AgentIsOnline(ctx, agentID)
}
