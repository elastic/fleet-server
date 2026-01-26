// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration

package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/docker/go-units"
	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/file"
	"github.com/elastic/fleet-server/v7/internal/pkg/file/uploader"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	itesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	"github.com/elastic/go-elasticsearch/v8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

/*
  Upload Begin route testing
*/

const RouteUploadBegin = "/api/fleet/uploads"

func TestUploadBeginValidation(t *testing.T) {
	hr, _, _, _ := prepareUploaderMock(t)

	// test empty body
	rec := httptest.NewRecorder()
	hr.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, RouteUploadBegin, nil))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "body is required")

	// now test various body contents
	tests := []struct {
		Name           string
		ExpectStatus   int
		ExpectContains string
		Input          string
	}{
		{"Zero length body is rejected", http.StatusBadRequest, "", ""},
		{"Minimum required body", http.StatusOK, "upload_id",
			`{
				"file": {
					"size": 200,
					"name": "foo.png",
					"mime_type": "image/png"
				},
				"agent_id": "foo",
				"action_id": "123",
				"src": "agent"
			}`,
		},
		{"Oversized file should be rejected", http.StatusBadRequest, "size",
			`{
				"file": {
					"size": ` + strconv.Itoa(maxFileSize+1024) + `,
					"name": "foo.png",
					"mime_type": "image/png"
				},
				"agent_id": "foo",
				"action_id": "123",
				"src": "agent"
			}`,
		},
		{"zero size file should be rejected", http.StatusBadRequest, "size",
			`{
				"file": {
					"size": 0,
					"name": "foo.png",
					"mime_type": "image/png"
				},
				"agent_id": "foo",
				"action_id": "123",
				"src": "agent"
			}`,
		},
		{"negative size file should be rejected", http.StatusBadRequest, "size",
			`{
				"file": {
					"size": -100,
					"name": "foo.png",
					"mime_type": "image/png"
				},
				"agent_id": "foo",
				"action_id": "123",
				"src": "agent"
			}`,
		},
		{"file size is required", http.StatusBadRequest, "file.size is required",
			`{
				"file": {
					"name": "foo.png",
					"mime_type": "image/png"
				},
				"agent_id": "foo",
				"action_id": "123",
				"src": "agent"
			}`,
		},
		{
			"UploadBegin request payload that is too large is rejected", http.StatusRequestEntityTooLarge, "the request body exceeds the maximum allowed size",
			generateLargePayload(2 * units.KB),
		},
		{"file name is required", http.StatusBadRequest, "file.name is required",
			`{
				"file": {
					"size": 100,
					"mime_type": "image/png"
				},
				"agent_id": "foo",
				"action_id": "123",
				"src": "agent"
			}`,
		},
		{"file name must not be empty", http.StatusBadRequest, "file.name",
			`{
				"file": {
					"size": 100,
					"name": "",
					"mime_type": "image/png"
				},
				"agent_id": "foo",
				"action_id": "123",
				"src": "agent"
			}`,
		},
		{"file mime_type is required", http.StatusBadRequest, "mime_type",
			`{
				"file": {
					"size": 100,
					"name": "foo.png"
				},
				"agent_id": "foo",
				"action_id": "123",
				"src": "agent"
			}`,
		},
		{"agent_id is required", http.StatusBadRequest, "agent_id",
			`{
				"file": {
					"size": 100,
					"name": "foo.png",
					"mime_type": "image/png"
				},
				"action_id": "123",
				"src": "agent"
			}`,
		},
		{"action_id is required", http.StatusBadRequest, "action_id",
			`{
				"file": {
					"size": 100,
					"name": "foo.png",
					"mime_type": "image/png"
				},
				"agent_id": "foo",
				"src": "agent"
			}`,
		},
		{"action_id must not be empty", http.StatusBadRequest, "action_id",
			`{
				"file": {
					"size": 100,
					"name": "foo.png",
					"mime_type": "image/png"
				},
				"agent_id": "foo",
				"action_id": "",
				"src": "agent"
			}`,
		},
		{"src is required", http.StatusBadRequest, "src",
			`{
				"file": {
					"size": 100,
					"name": "foo.png",
					"mime_type": "image/png"
				},
				"agent_id": "foo",
				"action_id": "123"
			}`,
		},
		{"src must not be empty", http.StatusBadRequest, "src",
			`{
				"file": {
					"size": 100,
					"name": "foo.png",
					"mime_type": "image/png"
				},
				"agent_id": "foo",
				"action_id": "123",
				"src":""
			}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			rec = httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, RouteUploadBegin, strings.NewReader(tc.Input))
			hr.ServeHTTP(rec, req)
			assert.Equal(t, tc.ExpectStatus, rec.Code)
			if tc.ExpectContains != "" {
				assert.Contains(t, rec.Body.String(), tc.ExpectContains)
			}

		})
	}

}

func TestUploadBeginAuth(t *testing.T) {

	tests := []struct {
		Name               string
		AuthSuccess        bool
		AgentFromAPIKey    string
		AgentInRequestBody string
		ExpectStatus       int
	}{
		{"Agent ID matching API Key succeeds", true, "abc123", "abc123", http.StatusOK},
		{"Agent ID not matching API Key should reject", true, "oneID", "differentID", http.StatusForbidden},
		{"Bad auth should reject request", false, "", "IDinDoc", http.StatusUnauthorized},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {

			hr, rt, _, _ := prepareUploaderMock(t)
			if !tc.AuthSuccess {
				rt.ut.authAPIKey = func(r *http.Request, b bulk.Bulk, c cache.Cache) (*apikey.APIKey, error) {
					return nil, apikey.ErrInvalidToken
				}
				rt.ut.authAgent = func(r *http.Request, s *string, b bulk.Bulk, c cache.Cache) (*model.Agent, error) {
					return nil, apikey.ErrInvalidToken
				}
			} else {
				rt.ut.authAgent = func(r *http.Request, s *string, b bulk.Bulk, c cache.Cache) (*model.Agent, error) {
					if *s != tc.AgentFromAPIKey { // real AuthAgent provides this facility
						return nil, ErrAgentIdentity
					}
					return &model.Agent{
						ESDocument: model.ESDocument{
							Id: tc.AgentFromAPIKey,
						},
						Agent: &model.AgentMetadata{
							ID: tc.AgentFromAPIKey,
						},
					}, nil
				}
			}

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, RouteUploadBegin, strings.NewReader(mockStartBodyWithAgent(tc.AgentInRequestBody)))
			hr.ServeHTTP(rec, req)

			assert.Equal(t, tc.ExpectStatus, rec.Code)
		})
	}

}

func TestUploadBeginResponse(t *testing.T) {
	hr, _, _, _ := prepareUploaderMock(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, RouteUploadBegin, strings.NewReader(mockStartBodyWithAgent("foo")))
	hr.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var response UploadBeginAPIResponse
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoErrorf(t, err, "upload start should provide valid JSON response")

	assert.NotEmptyf(t, response.UploadId, "upload start response should provide an ID")
	assert.Greaterf(t, response.ChunkSize, int64(0), "upload start response should provide a chunk size > 0")
}

func TestUploadBeginWritesTimestampToMeta(t *testing.T) {
	hr, _, fakebulk, _ := prepareUploaderMock(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, RouteUploadBegin, strings.NewReader(mockStartBodyWithAgent("foo")))
	hr.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	fakebulk.AssertCalled(t, "Create",
		mock.Anything, // context
		mock.MatchedBy(func(idx string) bool { return strings.HasPrefix(idx, ".fleet-fileds-fromhost-meta") }), // index
		mock.Anything, // file document ID -- generated, so can be any value
		mock.MatchedBy(func(body []byte) bool {
			doc := make(map[string]interface{})

			err := json.Unmarshal(body, &doc)
			require.NoError(t, err)
			if err != nil {
				return false
			}

			assert.Contains(t, doc, "@timestamp")

			var ts int64
			switch n := doc["@timestamp"].(type) {
			case string:
				ts, err = strconv.ParseInt(n, 10, 64)
				require.NoError(t, err)
			case uint64:
				ts = int64(n)
			case int64:
				ts = n
			case int:
				ts = int64(n)
			case float64:
				ts = int64(n)
			default:
				assert.Failf(t, "unknown @timestamp", "type was: %T", doc["@timestamp"])
			}
			assert.WithinDuration(t, time.Now(), time.UnixMilli(ts), 5*time.Second)
			return true
		}),
		mock.Anything, // upload Opts
	)
}

func TestUploadBeginBadRequest(t *testing.T) {
	hr, _, _, _ := prepareUploaderMock(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, RouteUploadBegin, strings.NewReader("not a json"))
	hr.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

/*
  Chunk data upload route
*/

func TestChunkUploadRouteParams(t *testing.T) {
	data := []byte("filedata")
	hasher := sha256.New()
	_, err := hasher.Write(data)
	require.NoError(t, err)
	hash := hex.EncodeToString(hasher.Sum(nil))
	mockUploadID := "abc123"

	tests := []struct {
		Name              string
		Path              string
		ExpectStatus      int
		ExpectErrContains string
	}{
		{"Valid chunk number is OK", "/api/fleet/uploads/" + mockUploadID + "/0", http.StatusOK, ""},
		{"Non-numeric chunk number is rejected", "/api/fleet/uploads/" + mockUploadID + "/CHUNKNUM", http.StatusBadRequest, "error binding string parameter"},
		{"Negative chunk number is rejected", "/api/fleet/uploads/" + mockUploadID + "/-2", http.StatusBadRequest, "invalid chunk number"},
		{"Too large chunk number is rejected", "/api/fleet/uploads/" + mockUploadID + "/50", http.StatusBadRequest, "invalid chunk number"},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {

			hr, _, fakebulk, _ := prepareUploaderMock(t)
			mockUploadInfoResult(fakebulk, file.Info{
				DocID:     "bar.foo",
				ID:        mockUploadID,
				ChunkSize: maxFileSize,
				Total:     file.MaxChunkSize + 1,
				Count:     2, // this is a 2-chunk "file" based on size above
				Start:     time.Now(),
				Status:    file.StatusProgress,
				Source:    "agent",
				AgentID:   "foo",
				ActionID:  "bar",
			})

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPut, tc.Path, bytes.NewReader(data))
			req.Header.Set("X-Chunk-SHA2", hash)

			hr.ServeHTTP(rec, req)

			assert.Equal(t, tc.ExpectStatus, rec.Code)
			if tc.ExpectErrContains != "" {
				assert.Contains(t, rec.Body.String(), tc.ExpectErrContains)
			}
		})
	}

}

func TestChunkUploadRequiresChunkHashHeader(t *testing.T) {
	data := []byte("filedata")
	mockUploadID := "abc123"

	hr, _, fakebulk, _ := prepareUploaderMock(t)
	mockUploadInfoResult(fakebulk, file.Info{
		DocID:     "bar.foo",
		ID:        mockUploadID,
		ChunkSize: maxFileSize,
		Total:     10,
		Count:     1,
		Start:     time.Now(),
		Status:    file.StatusProgress,
		Source:    "agent",
		AgentID:   "foo",
		ActionID:  "bar",
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/fleet/uploads/"+mockUploadID+"/0", bytes.NewReader(data))
	hr.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "Header parameter X-Chunk-SHA2 is required, but not found")

}

func TestChunkUploadStatus(t *testing.T) {
	data := []byte("filedata")
	hasher := sha256.New()
	_, err := hasher.Write(data)
	require.NoError(t, err)
	hash := hex.EncodeToString(hasher.Sum(nil))

	mockUploadID := "abc123"

	tests := []struct {
		Name              string
		Status            file.Status
		ExpectStatus      int
		ExpectErrContains string
	}{
		{"Can upload for Status Awaiting", file.StatusAwaiting, http.StatusOK, ""},
		{"Can upload for in progress", file.StatusProgress, http.StatusOK, ""},
		{"Status Delete Files cannot upload", file.StatusDel, http.StatusBadRequest, "stopped"},
		{"Status Complete File cannot upload", file.StatusDone, http.StatusBadRequest, "stopped"},
		{"Status Failure File cannot upload", file.StatusFail, http.StatusBadRequest, "stopped"},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {

			hr, _, fakebulk, _ := prepareUploaderMock(t)
			mockUploadInfoResult(fakebulk, file.Info{
				DocID:     "bar.foo",
				ID:        mockUploadID,
				ChunkSize: maxFileSize,
				Total:     10,
				Count:     1,
				Start:     time.Now(),
				Status:    tc.Status,
				Source:    "agent",
				AgentID:   "foo",
				ActionID:  "bar",
			})

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPut, "/api/fleet/uploads/"+mockUploadID+"/0", bytes.NewReader(data))
			req.Header.Set("X-Chunk-SHA2", hash)

			hr.ServeHTTP(rec, req)

			assert.Equal(t, tc.ExpectStatus, rec.Code)
			if tc.ExpectErrContains != "" {
				assert.Contains(t, rec.Body.String(), tc.ExpectErrContains)
			}
		})
	}

}

func TestChunkUploadExpiry(t *testing.T) {
	data := []byte("filedata")
	hasher := sha256.New()
	_, err := hasher.Write(data)
	require.NoError(t, err)
	hash := hex.EncodeToString(hasher.Sum(nil))

	mockUploadID := "abc123"

	tests := []struct {
		Name              string
		StartTime         time.Time
		ExpectStatus      int
		ExpectErrContains string
	}{
		{"Unexpired upload succeeds", time.Now().Add(-time.Minute), http.StatusOK, ""},
		{"Expired Upload rejects", time.Now().Add(-maxUploadTimer * 2), http.StatusBadRequest, "expired"},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {

			hr, _, fakebulk, _ := prepareUploaderMock(t)
			mockUploadInfoResult(fakebulk, file.Info{
				DocID:     "bar.foo",
				ID:        mockUploadID,
				ChunkSize: maxFileSize,
				Total:     10,
				Count:     1,
				Start:     tc.StartTime,
				Status:    file.StatusAwaiting,
				Source:    "agent",
				AgentID:   "foo",
				ActionID:  "bar",
			})

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPut, "/api/fleet/uploads/"+mockUploadID+"/0", bytes.NewReader(data))
			req.Header.Set("X-Chunk-SHA2", hash)

			hr.ServeHTTP(rec, req)

			assert.Equal(t, tc.ExpectStatus, rec.Code)
			if tc.ExpectErrContains != "" {
				assert.Contains(t, rec.Body.String(), tc.ExpectErrContains)
			}
		})
	}

}

func TestChunkUploadWritesTimestamp(t *testing.T) {
	data := []byte("filedata")
	hasher := sha256.New()
	_, err := hasher.Write(data)
	require.NoError(t, err)
	hash := hex.EncodeToString(hasher.Sum(nil))

	mockUploadID := "abc123"

	hr, _, fakebulk, mtx := prepareUploaderMock(t)
	mockUploadInfoResult(fakebulk, file.Info{
		DocID:     "bar.foo",
		ID:        mockUploadID,
		ChunkSize: maxFileSize,
		Total:     10,
		Count:     1,
		Start:     time.Now(),
		Status:    file.StatusAwaiting,
		Source:    "agent",
		AgentID:   "foo",
		ActionID:  "bar",
	})

	mtx.RoundTripFn = func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		require.NoError(t, err)

		assert.True(t, bytes.Contains(body, []byte("@timestamp")), "@timestamp should exist in chunk body")
		return mtx.Response, nil
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/fleet/uploads/"+mockUploadID+"/0", bytes.NewReader(data))
	req.Header.Set("X-Chunk-SHA2", hash)

	hr.ServeHTTP(rec, req)
}

/*
	Upload finalization route testing
*/

func TestUploadCompleteRequiresMatchingAuth(t *testing.T) {
	tests := []struct {
		Name              string
		AuthSuccess       bool
		AgentFromAPIKey   string
		AgentInFileRecord string
		ExpectStatus      int
	}{
		{"Agent ID matching API Key succeeds", true, "abc123", "abc123", http.StatusOK},
		{"Agent ID in File not matching API Key should reject", true, "oneID", "differentID", http.StatusForbidden},
		{"Bad auth should reject request", false, "", "IDinDoc", http.StatusUnauthorized},
	}
	mockUploadID := "abc123"

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {

			hr, rt, fakebulk, _ := prepareUploaderMock(t)
			mockInfo := file.Info{
				DocID:     "bar." + tc.AgentInFileRecord,
				ID:        mockUploadID,
				ChunkSize: maxFileSize,
				Total:     10,
				Count:     1,
				Start:     time.Now().Add(-time.Minute),
				Status:    file.StatusAwaiting,
				Source:    "agent",
				AgentID:   tc.AgentInFileRecord,
				ActionID:  "bar",
			}

			transit := mockUploadedFile(fakebulk, mockInfo, []file.ChunkInfo{{
				Last: true,
				Pos:  0,
				SHA2: "0c4a81b85a6b7ff00bde6c32e1e8be33b4b793b3b7b5cb03db93f77f7c9374d1", // sample value
				BID:  mockInfo.DocID,
				Size: int(mockInfo.Total),
			}})

			if !tc.AuthSuccess {
				rt.ut.authAPIKey = func(r *http.Request, b bulk.Bulk, c cache.Cache) (*apikey.APIKey, error) {
					return nil, apikey.ErrInvalidToken
				}
				rt.ut.authAgent = func(r *http.Request, s *string, b bulk.Bulk, c cache.Cache) (*model.Agent, error) {
					return nil, apikey.ErrInvalidToken
				}
			} else {
				rt.ut.authAgent = func(r *http.Request, s *string, b bulk.Bulk, c cache.Cache) (*model.Agent, error) {
					if *s != tc.AgentFromAPIKey { // real AuthAgent provides this facility
						return nil, ErrAgentIdentity
					}
					return &model.Agent{
						Agent: &model.AgentMetadata{
							ID: tc.AgentFromAPIKey,
						},
					}, nil
				}
			}

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/fleet/uploads/"+mockUploadID, strings.NewReader(`{"transithash":{"sha256":"`+transit+`"}}`))
			hr.ServeHTTP(rec, req)

			assert.Equal(t, tc.ExpectStatus, rec.Code)
		})
	}
}

func TestUploadCompleteRequiresValidStatus(t *testing.T) {
	mockUploadID := "abc123"

	tests := []struct {
		Name              string
		Status            file.Status
		ExpectStatus      int
		ExpectErrContains string
	}{
		{"Can finalize Status Awaiting", file.StatusAwaiting, http.StatusOK, ""},
		{"Can finalize Status in progress", file.StatusProgress, http.StatusOK, ""},
		{"Cannot finalize Status Deleted", file.StatusDel, http.StatusBadRequest, "closed"},
		{"Cannot finalize Status Complete", file.StatusDone, http.StatusBadRequest, "closed"},
		{"Cannot finalize Status Failure", file.StatusFail, http.StatusBadRequest, "closed"},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {

			hr, _, fakebulk, _ := prepareUploaderMock(t)
			mockInfo := file.Info{
				DocID:     "bar.foo",
				ID:        mockUploadID,
				ChunkSize: file.MaxChunkSize,
				Total:     10,
				Count:     1,
				Start:     time.Now().Add(-time.Minute),
				Status:    tc.Status,
				Source:    "agent",
				AgentID:   "foo",
				ActionID:  "bar",
			}

			transit := mockUploadedFile(fakebulk, mockInfo, []file.ChunkInfo{{
				Last: true,
				BID:  mockInfo.DocID,
				Size: int(mockInfo.Total),
				Pos:  0,
				SHA2: "0c4a81b85a6b7ff00bde6c32e1e8be33b4b793b3b7b5cb03db93f77f7c9374d1", // sample value
			}})

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/fleet/uploads/"+mockUploadID, strings.NewReader(`{"transithash": {"sha256": "`+transit+`"}}`))

			hr.ServeHTTP(rec, req)

			assert.Equal(t, tc.ExpectStatus, rec.Code)
			if tc.ExpectErrContains != "" {
				assert.Contains(t, rec.Body.String(), tc.ExpectErrContains)
			}
		})
	}
}

func TestUploadCompleteRejectsMissingChunks(t *testing.T) {
	mockUploadID := "abc123"

	hr, _, fakebulk, _ := prepareUploaderMock(t)
	mockInfo := file.Info{
		DocID:     "bar.foo",
		ID:        mockUploadID,
		ChunkSize: file.MaxChunkSize,
		Total:     file.MaxChunkSize * 3,
		Count:     3,
		Start:     time.Now().Add(-time.Minute),
		Status:    file.StatusProgress,
		Source:    "agent",
		AgentID:   "foo",
		ActionID:  "bar",
	}

	transit := mockUploadedFile(fakebulk, mockInfo, []file.ChunkInfo{
		{
			Last: false,
			BID:  mockInfo.DocID,
			Size: int(file.MaxChunkSize),
			Pos:  0,
			SHA2: "0c4a81b85a6b7ff00bde6c32e1e8be33b4b793b3b7b5cb03db93f77f7c9374d1", // sample value
		},
		// chunk position 1 omitted
		{
			Last: true,
			BID:  mockInfo.DocID,
			Size: int(file.MaxChunkSize),
			Pos:  2,
			SHA2: "0c4a81b85a6b7ff00bde6c32e1e8be33b4b793b3b7b5cb03db93f77f7c9374d1", // sample value
		},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/fleet/uploads/"+mockUploadID, strings.NewReader(`{"transithash": {"sha256": "`+transit+`"}}`))

	hr.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "incomplete")
}

func TestUploadCompleteRejectsFinalChunkNotMarkedFinal(t *testing.T) {
	mockUploadID := "abc123"

	hr, _, fakebulk, _ := prepareUploaderMock(t)
	mockInfo := file.Info{
		DocID:     "bar.foo",
		ID:        mockUploadID,
		ChunkSize: file.MaxChunkSize,
		Total:     file.MaxChunkSize * 3,
		Count:     3,
		Start:     time.Now().Add(-time.Minute),
		Status:    file.StatusProgress,
		Source:    "agent",
		AgentID:   "foo",
		ActionID:  "bar",
	}

	transit := mockUploadedFile(fakebulk, mockInfo, []file.ChunkInfo{
		{
			Last: false,
			BID:  mockInfo.DocID,
			Size: int(file.MaxChunkSize),
			Pos:  0,
			SHA2: "0c4a81b85a6b7ff00bde6c32e1e8be33b4b793b3b7b5cb03db93f77f7c9374d1", // sample value
		},
		{
			Last: false,
			BID:  mockInfo.DocID,
			Size: int(file.MaxChunkSize),
			Pos:  1,
			SHA2: "0c4a81b85a6b7ff00bde6c32e1e8be33b4b793b3b7b5cb03db93f77f7c9374d1", // sample value
		},
		{
			Last: false,
			BID:  mockInfo.DocID,
			Size: int(file.MaxChunkSize),
			Pos:  2,
			SHA2: "0c4a81b85a6b7ff00bde6c32e1e8be33b4b793b3b7b5cb03db93f77f7c9374d1", // sample value
		},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/fleet/uploads/"+mockUploadID, strings.NewReader(`{"transithash": {"sha256": "`+transit+`"}}`))

	hr.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "failed validation")
}

func TestUploadCompleteNonFinalChunkMarkedFinal(t *testing.T) {
	mockUploadID := "abc123"

	hr, _, fakebulk, _ := prepareUploaderMock(t)
	mockInfo := file.Info{
		DocID:     "bar.foo",
		ID:        mockUploadID,
		ChunkSize: file.MaxChunkSize,
		Total:     file.MaxChunkSize * 3,
		Count:     3,
		Start:     time.Now().Add(-time.Minute),
		Status:    file.StatusProgress,
		Source:    "agent",
		AgentID:   "foo",
		ActionID:  "bar",
	}

	transit := mockUploadedFile(fakebulk, mockInfo, []file.ChunkInfo{
		{
			Last: false,
			BID:  mockInfo.DocID,
			Size: int(file.MaxChunkSize),
			Pos:  0,
			SHA2: "0c4a81b85a6b7ff00bde6c32e1e8be33b4b793b3b7b5cb03db93f77f7c9374d1", // sample value
		},
		{
			Last: true,
			BID:  mockInfo.DocID,
			Size: int(file.MaxChunkSize),
			Pos:  1,
			SHA2: "0c4a81b85a6b7ff00bde6c32e1e8be33b4b793b3b7b5cb03db93f77f7c9374d1", // sample value
		},
		{
			Last: true,
			BID:  mockInfo.DocID,
			Size: int(file.MaxChunkSize),
			Pos:  2,
			SHA2: "0c4a81b85a6b7ff00bde6c32e1e8be33b4b793b3b7b5cb03db93f77f7c9374d1", // sample value
		},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/fleet/uploads/"+mockUploadID, strings.NewReader(`{"transithash": {"sha256": "`+transit+`"}}`))

	hr.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "failed validation")
}

func TestUploadCompleteUndersizedChunk(t *testing.T) {
	mockUploadID := "abc123"

	hr, _, fakebulk, _ := prepareUploaderMock(t)
	mockInfo := file.Info{
		DocID:     "bar.foo",
		ID:        mockUploadID,
		ChunkSize: file.MaxChunkSize,
		Total:     file.MaxChunkSize * 3,
		Count:     3,
		Start:     time.Now().Add(-time.Minute),
		Status:    file.StatusProgress,
		Source:    "agent",
		AgentID:   "foo",
		ActionID:  "bar",
	}

	transit := mockUploadedFile(fakebulk, mockInfo, []file.ChunkInfo{
		{
			Last: false,
			BID:  mockInfo.DocID,
			Size: int(file.MaxChunkSize),
			Pos:  0,
			SHA2: "0c4a81b85a6b7ff00bde6c32e1e8be33b4b793b3b7b5cb03db93f77f7c9374d1", // sample value
		},
		{
			Last: false,
			BID:  mockInfo.DocID,
			Size: int(file.MaxChunkSize) - 5,
			Pos:  1,
			SHA2: "0c4a81b85a6b7ff00bde6c32e1e8be33b4b793b3b7b5cb03db93f77f7c9374d1", // sample value
		},
		{
			Last: true,
			BID:  mockInfo.DocID,
			Size: int(file.MaxChunkSize),
			Pos:  2,
			SHA2: "0c4a81b85a6b7ff00bde6c32e1e8be33b4b793b3b7b5cb03db93f77f7c9374d1", // sample value
		},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/fleet/uploads/"+mockUploadID, strings.NewReader(`{"transithash": {"sha256": "`+transit+`"}}`))

	hr.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "failed validation")
}

func TestUploadCompleteIncorrectTransitHash(t *testing.T) {
	mockUploadID := "abc123"

	hr, _, fakebulk, _ := prepareUploaderMock(t)
	mockInfo := file.Info{
		DocID:     "bar.foo",
		ID:        mockUploadID,
		ChunkSize: file.MaxChunkSize,
		Total:     file.MaxChunkSize * 3,
		Count:     3,
		Start:     time.Now().Add(-time.Minute),
		Status:    file.StatusProgress,
		Source:    "agent",
		AgentID:   "foo",
		ActionID:  "bar",
	}

	mockUploadedFile(fakebulk, mockInfo, []file.ChunkInfo{
		{
			Last: false,
			BID:  mockInfo.DocID,
			Size: int(file.MaxChunkSize),
			Pos:  0,
			SHA2: "0c4a81b85a6b7ff00bde6c32e1e8be33b4b793b3b7b5cb03db93f77f7c9374d1", // sample value
		},
		{
			Last: false,
			BID:  mockInfo.DocID,
			Size: int(file.MaxChunkSize) - 5,
			Pos:  1,
			SHA2: "0c4a81b85a6b7ff00bde6c32e1e8be33b4b793b3b7b5cb03db93f77f7c9374d1", // sample value
		},
		{
			Last: true,
			BID:  mockInfo.DocID,
			Size: int(file.MaxChunkSize),
			Pos:  2,
			SHA2: "0c4a81b85a6b7ff00bde6c32e1e8be33b4b793b3b7b5cb03db93f77f7c9374d1", // sample value
		},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/fleet/uploads/"+mockUploadID, strings.NewReader(`{"transithash": {"sha256": "wrongHash"}}`))

	hr.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "failed validation")
}

func TestUploadCompleteBadRequests(t *testing.T) {
	mockUploadID := "abc123"

	hr, _, fakebulk, _ := prepareUploaderMock(t)
	mockInfo := file.Info{
		DocID:     "bar.foo",
		ID:        mockUploadID,
		ChunkSize: file.MaxChunkSize,
		Total:     file.MaxChunkSize * 3,
		Count:     3,
		Start:     time.Now().Add(-time.Minute),
		Status:    file.StatusProgress,
		Source:    "agent",
		AgentID:   "foo",
		ActionID:  "bar",
	}

	mockUploadedFile(fakebulk, mockInfo, []file.ChunkInfo{
		{
			Last: false,
			BID:  mockInfo.DocID,
			Size: int(file.MaxChunkSize),
			Pos:  0,
			SHA2: "0c4a81b85a6b7ff00bde6c32e1e8be33b4b793b3b7b5cb03db93f77f7c9374d1", // sample value
		},
		{
			Last: true,
			BID:  mockInfo.DocID,
			Size: int(file.MaxChunkSize),
			Pos:  1,
			SHA2: "0c4a81b85a6b7ff00bde6c32e1e8be33b4b793b3b7b5cb03db93f77f7c9374d1", // sample value
		},
		{
			Last: true,
			BID:  mockInfo.DocID,
			Size: int(file.MaxChunkSize),
			Pos:  2,
			SHA2: "0c4a81b85a6b7ff00bde6c32e1e8be33b4b793b3b7b5cb03db93f77f7c9374d1", // sample value
		},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/fleet/uploads/"+mockUploadID, strings.NewReader(`{"transithash": {"sha256": `))

	hr.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, rec.Body.String(), "{\"statusCode\":400,\"error\":\"BadRequest\",\"message\":\"Bad request: unable to decode upload complete request\"}")
}

func TestUploadCompletePayloadSize(t *testing.T) {
	mockUploadID := "abc123"

	hr, _, fakebulk, _ := prepareUploaderMock(t)
	mockInfo := file.Info{
		DocID:     "bar.foo",
		ID:        mockUploadID,
		ChunkSize: file.MaxChunkSize,
		Total:     file.MaxChunkSize * 3,
		Count:     3,
		Start:     time.Now().Add(-time.Minute),
		Status:    file.StatusProgress,
		Source:    "agent",
		AgentID:   "foo",
		ActionID:  "bar",
	}

	mockUploadedFile(fakebulk, mockInfo, []file.ChunkInfo{
		{
			Last: false,
			BID:  mockInfo.DocID,
			Size: int(file.MaxChunkSize),
			Pos:  0,
			SHA2: "0c4a81b85a6b7ff00bde6c32e1e8be33b4b793b3b7b5cb03db93f77f7c9374d1", // sample value
		},
		{
			Last: true,
			BID:  mockInfo.DocID,
			Size: int(file.MaxChunkSize),
			Pos:  1,
			SHA2: "0c4a81b85a6b7ff00bde6c32e1e8be33b4b793b3b7b5cb03db93f77f7c9374d1", // sample value
		},
		{
			Last: true,
			BID:  mockInfo.DocID,
			Size: int(file.MaxChunkSize),
			Pos:  2,
			SHA2: "0c4a81b85a6b7ff00bde6c32e1e8be33b4b793b3b7b5cb03db93f77f7c9374d1", // sample value
		},
	})

	longHash := strings.Repeat("a", 2*units.KB)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/fleet/uploads/"+mockUploadID,
		strings.NewReader(`{"transithash": {"sha256": "`+longHash+`"}}`),
	)

	hr.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	assert.Equal(t, rec.Body.String(), `{"statusCode":413,"error":"ErrPayloadSizeTooLarge","message":"the request body exceeds the maximum allowed size"}`)
}

/*
	Helpers and mocks
*/

// prepareUploaderMock sets up common dependencies and registers upload routes to a returned router
func prepareUploaderMock(t *testing.T) (http.Handler, apiServer, *itesting.MockBulk, *MockTransport) {
	// chunk index operations skip the bulker in order to send binary docs directly
	// so a mock *elasticsearch.Client needs to be be prepared
	es, tx := mockESClient(t)

	fakebulk := itesting.NewMockBulk()
	fakebulk.On("Create",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return("", nil)
	fakebulk.On("Update",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(nil)
	fakebulk.On("Client",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(es, nil)

	c, err := cache.New(config.Cache{NumCounters: 100, MaxCost: 100000})
	require.NoError(t, err)

	cfg := config.Server{Limits: config.ServerLimits{
		UploadStartLimit: config.Limit{MaxBody: 1 * units.KB},
		UploadEndLimit:   config.Limit{MaxBody: 1 * units.KB},
	}}

	// create an apiServer with an UploadT that will handle the incoming requests
	si := apiServer{
		ut: &UploadT{
			cfg:         &cfg,
			bulker:      fakebulk,
			chunkClient: es,
			cache:       c,
			uploader:    uploader.New(es, fakebulk, c, maxFileSize, maxUploadTimer),
			authAgent: func(r *http.Request, id *string, bulker bulk.Bulk, c cache.Cache) (*model.Agent, error) {
				return &model.Agent{
					ESDocument: model.ESDocument{
						Id: "foo",
					},
					Agent: &model.AgentMetadata{
						ID: "foo",
					},
				}, nil
			},
			authAPIKey: func(r *http.Request, b bulk.Bulk, c cache.Cache) (*apikey.APIKey, error) {
				return nil, nil
			},
		},
	}

	return Handler(&si), si, fakebulk, tx
}

// mockStartBodyWithAgent returns the minimum required JSON payload for beginning an upload, with agent set as input
func mockStartBodyWithAgent(agent string) string {
	return `{
				"file": {
					"size": 200,
					"name": "foo.png",
					"mime_type": "image/png"
				},
				"agent_id": "` + agent + `",
				"action_id": "123",
				"src": "agent"
			}`
}

// mockUploadInfoResult sets up the MockBulk to return file metadata in the proper format
func mockUploadInfoResult(bulker *itesting.MockBulk, info file.Info) {

	// convert info into how it's stored/returned in ES
	out, _ := json.Marshal(map[string]interface{}{
		"action_id": info.ActionID,
		"agent_id":  info.AgentID,
		"src":       info.Source,
		"file": map[string]interface{}{
			"size":      info.Total,
			"ChunkSize": info.ChunkSize,
			"Status":    info.Status,
		},
		"upload_id":    info.ID,
		"upload_start": info.Start.UnixMilli(),
	})

	bulker.On("Search",
		mock.Anything,
		mock.MatchedBy(func(idx string) bool { return strings.HasPrefix(idx, ".fleet-fileds-fromhost-meta-") }),
		mock.Anything,
		mock.Anything,
	).Return(&es.ResultT{
		HitsT: es.HitsT{
			Hits: []es.HitT{
				{
					ID:     info.DocID,
					Source: out,
				},
			},
		},
	}, nil).Once()
}

// mockChunkResult sets up the MockBulk to return Chunk Data in the expected format from Elasticsearch
// it returns the transithash for the provided chunks
func mockChunkResult(bulker *itesting.MockBulk, chunks []file.ChunkInfo) string {

	results := make([]es.HitT, len(chunks))
	for i, chunk := range chunks {
		results[i] = es.HitT{
			ID: chunk.BID + "." + strconv.Itoa(chunk.Pos),
			Fields: map[string]interface{}{
				file.FieldBaseID: []interface{}{chunk.BID},
				file.FieldSHA2:   []interface{}{chunk.SHA2},
				file.FieldLast:   []interface{}{chunk.Last},
				"size":           []interface{}{chunk.Size},
			},
		}
	}

	bulker.On("Search",
		mock.Anything,
		mock.MatchedBy(func(idx string) bool { return strings.HasPrefix(idx, ".fleet-fileds-fromhost-data-") }),
		mock.Anything,
		mock.Anything,
	).Return(&es.ResultT{
		HitsT: es.HitsT{
			Hits: results,
		},
	}, nil)
	return calcTransitHash(chunks)
}

// mockUploadedFile places the expected data (file metadata and chunks) into the bulker
// to emulate an uploaded file
// it returns the transithash for the provided chunks
func mockUploadedFile(bulker *itesting.MockBulk, info file.Info, chunks []file.ChunkInfo) string {
	mockUploadInfoResult(bulker, info) // one result from the cache for agent ID check
	mockUploadInfoResult(bulker, info) // second for a cache-busting fetch for up-to-date status
	return mockChunkResult(bulker, chunks)
}

func calcTransitHash(chunks []file.ChunkInfo) string {
	hasher := sha256.New()
	for _, c := range chunks {
		out, err := hex.DecodeString(c.SHA2)
		if err != nil {
			panic(err)
		}
		_, _ = hasher.Write(out)
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

/*
	Setup to convert a *elasticsearch.Client as a harmless mock
	by replacing the Transport to nowhere
*/

type MockTransport struct {
	Response    *http.Response
	RoundTripFn func(req *http.Request) (*http.Response, error)
}

func (t *MockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.RoundTripFn(req)
}

func mockESClient(t *testing.T) (*elasticsearch.Client, *MockTransport) {
	mocktrans := MockTransport{
		Response: sendBodyString("{}"), //nolint:bodyclose // nopcloser is used, linter does not see it
	}

	mocktrans.RoundTripFn = func(req *http.Request) (*http.Response, error) { return mocktrans.Response, nil }
	client, err := elasticsearch.NewClient(elasticsearch.Config{
		Transport: &mocktrans,
	})
	require.NoError(t, err)
	return client, &mocktrans
}

func sendBodyString(body string) *http.Response { return sendBody(strings.NewReader(body)) }
func sendBodyBytes(body []byte) *http.Response  { return sendBody(bytes.NewReader(body)) }
func sendBody(body io.Reader) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       ioutil.NopCloser(body),
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
			"Content-Type":      []string{"application/cbor"},
		},
	}
}
<<<<<<< HEAD
=======

func size_ptr(x int) *uint64 {
	y := uint64(x) //nolint:gosec // disable G115
	return &y
}

func generateLargePayload(paddingSize int) string {
	payload := `{
  "file": {
    "size": 1,
    "name": "foo.png",
    "mime_type": "image/png"
  },
  "agent_id": "foo",
  "action_id": "123",
  "src": "agent",
  "pad": "%s"
}`
	padding := strings.Repeat("a", paddingSize)
	return fmt.Sprintf(payload, padding)
}
>>>>>>> b91dc36 (Enforce size limit on `POST /api/fleet/uploads` (#6159))
