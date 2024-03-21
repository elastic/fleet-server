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

	resp, err := client.AgentCheckinWithResponse(ctx, agentID, &api.AgentCheckinParams{UserAgent: "elastic agent " + version.DefaultVersion}, *requestBody)
	tester.Require().NoError(err)

	// No need to process the response further if we're testing for a bad request;
	// just return the status code
	// For valid requests, process as usual
	if resp.StatusCode() != http.StatusOK {
		return nil, nil, resp.StatusCode()
	}

	// Process a successful check-in response.
	checkin := resp.JSON200
	tester.Require().NotNil(checkin.AckToken, "expected to recieve ack token from checkin")
	tester.Require().NotNil(checkin.Actions, "expected to actions from checkin")

	actionIds := make([]string, len(*checkin.Actions))
	for i, action := range *checkin.Actions {
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

func (tester *ClientAPITester) GetPGPKey(ctx context.Context, apiKey string) []byte {
	client, err := api.NewClientWithResponses(tester.endpoint, api.WithHTTPClient(tester.Client), api.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "ApiKey "+apiKey)
		return nil
	}))
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
	tester.GetPGPKey(ctx, tester.enrollmentKey)
}
