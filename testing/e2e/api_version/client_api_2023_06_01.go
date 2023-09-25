// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build e2e

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
	"time"

	"github.com/elastic/fleet-server/testing/e2e/scaffold"
	"github.com/elastic/fleet-server/v7/pkg/api/versions/2022_06_01/api"

	"github.com/elastic/fleet-server/v7/version"
)

// ClientAPITester20230601 provides methods to test API endpoints
type ClientAPITester20230601 struct {
	*scaffold.Scaffold

	endpoint      string
	enrollmentKey string
}

func NewClientAPITester20230601(scaffold scaffold.Scaffold, endpoint, enrollmentKey string) *ClientAPITester20230601 {
	return &ClientAPITester20230601{
		&scaffold,
		endpoint,
		enrollmentKey,
	}
}

func (tester *ClientAPITester20230601) SetEndpoint(endpoint string) {
	tester.endpoint = endpoint
}

func (tester *ClientAPITester20230601) SetKey(key string) {
	tester.enrollmentKey = key
}

func (tester *ClientAPITester20230601) getAPIClient(withRequestEditorFn api.RequestEditorFn) (api.ClientWithResponsesInterface, error) {
	return api.NewClientWithResponses(tester.endpoint, api.WithHTTPClient(tester.Client), api.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
		req.Header.Set("elastic-api-version", "2023-06-01")

		if withRequestEditorFn != nil {
			return withRequestEditorFn(ctx, req)
		}

		return nil
	}))
}

// Status tests the status endpoint, if an apiKey is given the authenticated response if verfied.
func (tester *ClientAPITester20230601) Status(ctx context.Context, apiKey string) {
	client, err := tester.getAPIClient(nil)
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
	tester.Assert().Equal(http.StatusOK, resp.StatusCode())
	tester.Assert().NotEmpty(resp.JSON200.Name)
	tester.Assert().NotEmpty(resp.JSON200.Status)
	if apiKey != "" {
		tester.Assert().NotNil(resp.JSON200.Version)
	}
}

// Enroll tests the enroll endpoint with the given apiKey.
// Returns the agentID and agentAPIKey.
func (tester *ClientAPITester20230601) Enroll(ctx context.Context, apiKey string) (string, string) {
	client, err := tester.getAPIClient(func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "ApiKey "+apiKey)
		return nil
	})
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
	tester.Assert().Equal(http.StatusOK, enrollResp.StatusCode())

	enroll := enrollResp.JSON200
	tester.Assert().NotEmpty(enroll.Item.Id, "expected agent ID in response")
	tester.Assert().NotEmpty(enroll.Item.AccessApiKey, "expected agent API key in response")
	return enroll.Item.Id, enroll.Item.AccessApiKey
}

// Checkin tests the checkin endpoint.
// Returns the new ack token and the list of actions.
func (tester *ClientAPITester20230601) Checkin(ctx context.Context, apiKey, agentID string, ackToken, dur *string) (*string, []string) {
	client, err := tester.getAPIClient(func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "ApiKey "+apiKey)
		return nil
	})
	tester.Require().NoError(err)

	resp, err := client.AgentCheckinWithResponse(ctx,
		agentID,
		&api.AgentCheckinParams{UserAgent: "elastic agent " + version.DefaultVersion},
		api.AgentCheckinJSONRequestBody{
			Status:      api.CheckinRequestStatusOnline,
			AckToken:    ackToken,
			PollTimeout: dur,
		},
	)
	tester.Require().NoError(err)
	tester.Assert().Equal(http.StatusOK, resp.StatusCode())
	checkin := resp.JSON200
	tester.Assert().NotNil(checkin.AckToken, "expected to recieve ack token from checkin")
	tester.Assert().NotNil(checkin.Actions, "expected to actions from checkin")

	actionIds := make([]string, len(*checkin.Actions))
	for i, action := range *checkin.Actions {
		actionIds[i] = action.Id
	}

	return checkin.AckToken, actionIds
}

// Acks tests the acks endpoint
func (tester *ClientAPITester20230601) Acks(ctx context.Context, apiKey, agentID string, actionsIDs []string) {
	client, err := tester.getAPIClient(func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "ApiKey "+apiKey)
		return nil
	})
	tester.Require().NoError(err)

	events := make([]api.Event, 0, len(actionsIDs))
	for _, actionId := range actionsIDs {
		events = append(events, api.Event{
			ActionId: actionId,
			AgentId:  agentID,
		})
	}

	resp, err := client.AgentAcksWithResponse(ctx,
		agentID,
		&api.AgentAcksParams{},
		api.AgentAcksJSONRequestBody{
			Events: events,
		},
	)
	tester.Require().NoError(err)
	tester.Assert().Equal(http.StatusOK, resp.StatusCode())

	acks := resp.JSON200
	tester.Assert().Falsef(acks.Errors, "error in acked items: %v", acks.Items)
}

// FullFileUpload tests the file upload endpoints (begin, chunk, complete).
func (tester *ClientAPITester20230601) FullFileUpload(ctx context.Context, apiKey, agentID, actionID string, size int64) {
	client, err := tester.getAPIClient(func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "ApiKey "+apiKey)
		return nil
	})
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

// Artifact tests the artifact endpoint with the passed id and `sha2 values.
// The hash of the retrieved body is expected to be equal to encodedSHA
func (tester *ClientAPITester20230601) Artifact(ctx context.Context, apiKey, id, sha2, encodedSHA string) {
	client, err := tester.getAPIClient(func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "ApiKey "+apiKey)
		return nil
	})
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

func (tester *ClientAPITester20230601) TestStatus_Unauthenticated() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tester.Status(ctx, "")
}

func (tester *ClientAPITester20230601) TestStatus_Authenticated() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tester.Status(ctx, tester.enrollmentKey)
}

func (tester *ClientAPITester20230601) TestEnrollCheckinAck() {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	tester.T().Log("test enrollment")
	agentID, agentKey := tester.Enroll(ctx, tester.enrollmentKey)
	tester.VerifyAgentInKibana(ctx, agentID)

	tester.T().Logf("test checkin 1: agent %s", agentID)
	ackToken, actions := tester.Checkin(ctx, agentKey, agentID, nil, nil)
	tester.Require().NotEmpty(actions)

	tester.T().Log("test ack")
	tester.Acks(ctx, agentKey, agentID, actions)

	tester.T().Logf("test checkin 2: agent %s 3m timout", agentID)
	dur := "3m"

	tester.Checkin(ctx, agentKey, agentID, ackToken, &dur)

	// sanity check agent status in kibana
	tester.AgentIsOnline(ctx, agentID)
}

func (tester *ClientAPITester20230601) TestFullFileUpload() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agentID, agentKey := tester.Enroll(ctx, tester.enrollmentKey)
	actionID := tester.RequestDiagnosticsForAgent(ctx, agentID)

	tester.FullFileUpload(ctx, agentKey, agentID, actionID, 8192) // 8KiB file
}

func (tester *ClientAPITester20230601) TestArtifact() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	_, agentKey := tester.Enroll(ctx, tester.enrollmentKey)
	tester.AddSecurityContainer(ctx)
	tester.AddSecurityContainerItem(ctx)

	hits := tester.FleetHasArtifacts(ctx)
	tester.Artifact(ctx, agentKey, hits[0].Source.Identifier, hits[0].Source.DecodedSHA256, hits[0].Source.EncodedSHA256)
}
