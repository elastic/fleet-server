// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package uploader

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/file"
	itesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	"github.com/elastic/fleet-server/v7/internal/pkg/testing/esutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

/*
This test verifies that chunks are made available for search
before the Uploader performs that search and counts/verifies each chunk.
It specifically looks for an elasticsearch call to `../_refresh/` API,
to occur before a chunk-search call. This prevents the index-then-search
data race problem with final chunks *right before* completion API call.

If alternative means are used to address the data-race race condition,
this test may be updated.
*/
func TestUploadCompletePerformsRefreshBeforeChunkSearch(t *testing.T) {

	/**
	 *  Setup & Mocking only
	 *  avoid asserts here, since the setup path is involved, and executes
	 *  a lot of code paths. Those paths are not under test here
	**/
	refreshCalled := false
	size := 200
	fakeBulk := itesting.NewMockBulk()
	fakeIntegrationSrc := "endpoint"
	// hash of null chunk, and then transithash OF that hash
	nullHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	transitHashNull := "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
	mockClient, mockTX := esutil.MockESClient(t)

	// populate mock info for a *metadata* search, which may occur during finalization
	mockMeta, _ := json.Marshal(map[string]any{
		"action_id": "actionID",
		"agent_id":  "agentID",
		"src":       fakeIntegrationSrc,
		"file": map[string]interface{}{
			"size":      size,
			"ChunkSize": file.MaxChunkSize,
			"Status":    file.StatusProgress,
		},
		"upload_id":    "some-id",
		"upload_start": time.Now().UnixMilli(),
	})
	fakeBulk.On("Search",
		mock.MatchedBy(func(_ context.Context) bool { return true }), // match context.Context
		".fleet-fileds-fromhost-meta-*",                              // *metadata* index (NOT CHUNK/DATA!)
		mock.Anything,                                                // query bytes
		mock.Anything,                                                // bulk opts
	).Return(&es.ResultT{
		HitsT: es.HitsT{
			Hits: []es.HitT{{
				ID:     "_sampledocID",
				Source: mockMeta,
			}},
		},
	}, nil).Maybe() // not under test, calling is not required
	fakeBulk.On("Client").Return(mockClient).Maybe() // inject our mock client, if used
	mockTX.RoundTripFn = func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Path, fmt.Sprintf(UploadDataIndexPattern, fakeIntegrationSrc)+"/_refresh") {
			refreshCalled = true
		}
		respHeaders := make(http.Header)
		respHeaders.Set("X-Elastic-Product", "Elasticsearch")
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(`{}`)),
			Header:     respHeaders,
		}, nil
	}

	fakeBulk.On("Search",
		mock.MatchedBy(func(_ context.Context) bool { return true }), // match context.Context
		".fleet-fileds-fromhost-data-*",                              // *DATA* (chunk) search
		mock.Anything,                                                // query bytes
		mock.Anything,                                                // bulk opts

	).Run(func(args mock.Arguments) {
		// runs during execution, before return
		assert.True(t, refreshCalled, "Chunk finalization search occurred without refresh")
	}).Return(&es.ResultT{
		HitsT: es.HitsT{
			Hits: []es.HitT{{
				ID: "actionID.agentID.0",
				Fields: map[string]any{
					file.FieldBaseID: []any{"actionID.agentID"},
					file.FieldSHA2:   []any{nullHash},
					"size":           []any{size},
					file.FieldLast:   []any{true},
				},
			}},
		},
	}, nil)

	c, err := cache.New(config.Cache{NumCounters: 100, MaxCost: 100000})
	require.NoError(t, err) // panic-exit if prereq fails, not intentional testing
	u := New(nil, fakeBulk, c, size_ptr(size), time.Hour)

	/**
	 * Begin actual execution & assertions
	**/
	_, err = u.Complete(t.Context(), "actionID", transitHashNull)
	assert.NoError(t, err)

	assert.True(t, refreshCalled, "_refresh API was not called during file finalization")
}
