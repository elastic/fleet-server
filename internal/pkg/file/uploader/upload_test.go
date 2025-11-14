// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package uploader

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/file"
	itesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// convenience function for making a typical file request structure
// with defaults when specific values are not checked or required
func makeUploadRequestDict(input map[string]interface{}) JSDict {
	// defaults
	d := JSDict{
		"file": map[string]interface{}{
			"name":      "foo.png",
			"mime_type": "image/png",
			"size":      1024,
		},
		"action_id": "123",
		"agent_id":  "456",
		"src":       "agent",
	}

	if input == nil {
		return d
	}

	// fill in any provided values, e.g.  "file.name": "test.zip"
	for k, v := range input {
		dict := map[string]interface{}(d)
		keys := strings.Split(k, ".")
		for i, key := range keys {
			if i < len(keys)-1 {
				dict, _ = dict[key].(map[string]interface{})
				continue
			}
			dict[key] = v
		}
	}
	return d
}

// Happy-path case, where everything expected is provided
// tests to make sure the returned struct is correctly populated
func TestUploadBeginReturnsCorrectInfo(t *testing.T) {
	size := 2048
	src := "mysource"
	action := "abc"
	agent := "XYZ"
	data := makeUploadRequestDict(map[string]interface{}{
		"action_id": action,
		"agent_id":  agent,
		"src":       src,
		"file.size": size,
	})

	fakeBulk := itesting.NewMockBulk()

	fakeBulk.On("Create",
		mock.MatchedBy(func(_ context.Context) bool { return true }), // match context.Context
		".fleet-fileds-fromhost-meta-"+src,                           // index
		action+"."+agent,                                             // document ID
		mock.Anything,                                                // ES document
		mock.Anything,                                                // bulker options
	).Return("", nil)

	c, err := cache.New(config.Cache{NumCounters: 100, MaxCost: 100000})
	require.NoError(t, err)
	u := New(nil, fakeBulk, c, size_ptr(size), time.Hour)
	info, err := u.Begin(t.Context(), []string{}, data)
	assert.NoError(t, err)

	assert.Equal(t, int64(size), info.Total)
	assert.Equal(t, action, info.ActionID)
	assert.Equal(t, agent, info.AgentID)
	assert.Equal(t, src, info.Source)
	assert.Equal(t, file.StatusAwaiting, info.Status)
	assert.Greaterf(t, info.ChunkSize, int64(0), "server chosen chunk size should be >0")
	assert.Equal(t, action+"."+agent, info.DocID)
	assert.WithinDuration(t, time.Now(), info.Start, time.Minute)
}

// Happy-path case, where everything expected is provided
// tests the document sent to elasticsearch passes through
// the correct fields from input
func TestUploadBeginWritesDocumentFromInputs(t *testing.T) {
	size := 3096
	src := "foo"
	action := "abcd-ef"
	agent := "xyz-123"
	name := "test.zip"

	data := makeUploadRequestDict(map[string]interface{}{
		"action_id": action,
		"agent_id":  agent,
		"src":       src,
		"file.name": name,
		"file.size": size,
	})

	fakeBulk := itesting.NewMockBulk()

	fakeBulk.On("Create",
		mock.MatchedBy(func(_ context.Context) bool { return true }), // match context.Context
		".fleet-fileds-fromhost-meta-"+src,                           // index
		action+"."+agent,                                             // document ID
		mock.Anything,                                                // ES document
		mock.Anything,                                                // bulker options
	).Return("", nil)

	c, err := cache.New(config.Cache{NumCounters: 100, MaxCost: 100000})
	require.NoError(t, err)
	u := New(nil, fakeBulk, c, size_ptr(size), time.Hour)
	_, err = u.Begin(t.Context(), []string{}, data)
	assert.NoError(t, err)

	payload, ok := fakeBulk.Calls[0].Arguments[3].([]byte)
	assert.Truef(t, ok, "argument to es create should be byte slice")

	j := make(JSDict)
	err = json.Unmarshal(payload, &j)
	assert.NoError(t, err)

}

func TestUploadBeginCalculatesCorrectChunkCount(t *testing.T) {
	fakeBulk := itesting.NewMockBulk()

	fakeBulk.On("Create",
		mock.Anything, // match context.Context
		mock.Anything, // index
		mock.Anything, // document ID
		mock.Anything, // ES document
		mock.Anything, // bulker options
	).Return("", nil)

	tests := []struct {
		FileSize      int64
		ExpectedCount int
		Name          string
	}{
		{10, 1, "Tiny files take 1 chunk"},
		{file.MaxChunkSize, 1, "Precisely 1 chunk size bytes should fit in 1 chunk"},
		{file.MaxChunkSize + 1, 2, "ChunkSize+1 bytes takes 2 chunks"},
		{file.MaxChunkSize * 3.5, 4, "3.5x chunk size fits in 4 chunks due to remainder"},
		{7534559605, 1797, "7.5Gb file"},
	}

	c, err := cache.New(config.Cache{NumCounters: 100, MaxCost: 100000})
	require.NoError(t, err)
	u := New(nil, fakeBulk, c, size_ptr(file.MaxChunkSize*3000), time.Hour)

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			data := makeUploadRequestDict(map[string]interface{}{
				"file.size": tc.FileSize,
			})
			info, err := u.Begin(t.Context(), []string{}, data)
			assert.NoError(t, err)
			assert.Equal(t, tc.ExpectedCount, info.Count)
		})
	}
}

func TestUploadBeginMaxFileSize(t *testing.T) {

	tests := []struct {
		UploadSizeLimit *uint64
		FileSize        int64
		ShouldError     bool
		Name            string
	}{
		{size_ptr(0), 4096, true, "0 in config disables feature"},
		{size_ptr(10), 5, false, "any positive value should keep feature enabled"},
		{size_ptr(500), 800, true, "file of 800 is larger than limit 500"},
		{size_ptr(800), 500, false, "file within limits"},
		{size_ptr(1024), 1023, false, "1-less than limit"},
		{size_ptr(1024), 1024, false, "file is exactly limit"},
		{size_ptr(1024), 1025, true, "file is 1 over limit"},
		{nil, 1024 * 1024 * 300, false, "nil as limit is unlimited"},
	}

	fakeBulk := itesting.NewMockBulk()
	fakeBulk.On("Create",
		mock.Anything, // context.Context
		mock.Anything, // index
		mock.Anything, // document ID
		mock.Anything, // ES document
		mock.Anything, // bulker options
	).Return("", nil)

	c, err := cache.New(config.Cache{NumCounters: 100, MaxCost: 100000})
	require.NoError(t, err)

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			u := New(nil, fakeBulk, c, tc.UploadSizeLimit, time.Hour)
			data := makeUploadRequestDict(map[string]interface{}{
				"file.size": tc.FileSize,
			})
			_, err := u.Begin(t.Context(), []string{}, data)
			if tc.ShouldError {
				if tc.UploadSizeLimit != nil && *tc.UploadSizeLimit == 0 {
					assert.ErrorIs(t, err, ErrFeatureDisabled)
				} else {
					assert.ErrorIs(t, err, ErrFileSizeTooLarge)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestUploadRejectsMissingRequiredFields(t *testing.T) {

	tests := []string{
		"file.name",
		"file.mime_type",
		"file.size",
		"action_id",
		"agent_id",
		"src",
	}

	fakeBulk := itesting.NewMockBulk()
	fakeBulk.On("Create",
		mock.Anything, // match context.Context
		mock.Anything, // index
		mock.Anything, // document ID
		mock.Anything, // ES document
		mock.Anything, // bulker options
	).Return("", nil)

	c, err := cache.New(config.Cache{NumCounters: 100, MaxCost: 100000})
	require.NoError(t, err)

	u := New(nil, fakeBulk, c, size_ptr(2048), time.Hour)

	var ok bool
	for _, field := range tests {

		t.Run("required field "+field, func(t *testing.T) {
			// create input that already has all required fields
			data := makeUploadRequestDict(nil)

			// now delete this field and expect failure below
			d := map[string]interface{}(data)
			parts := strings.Split(field, ".")
			for i, part := range parts {
				if i == len(parts)-1 { // leaf of an object tree
					delete(d, part)
				} else {
					d, ok = d[part].(map[string]interface{})
					assert.Truef(t, ok, "incorrect key path '%s' when testing required fields", field)
				}
			}

			_, err = u.Begin(t.Context(), []string{}, data)
			assert.Errorf(t, err, "%s is a required field and should error if not provided", field)
		})

	}

}

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
		mock.Anything,
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

func TestChunkMarksFinal(t *testing.T) {
	tests := []struct {
		FileSize   int64
		FinalChunk int
		Name       string
	}{
		{10, 0, "Small file only chunk is final"},
		{file.MaxChunkSize, 0, "1 chunksize only chunk is final"},
		{file.MaxChunkSize + 1, 1, "ChunkSize+1 bytes takes 2 chunks"},
		{file.MaxChunkSize * 2.5, 2, "2.5x chunk size"},
		{7534559605, 1796, "7.5Gb file"},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {

			fakeBulk := itesting.NewMockBulk()
			fakeBulk.On("Create",
				mock.Anything, // match context.Context
				mock.Anything, // index
				mock.Anything, // document ID
				mock.Anything, // ES document
				mock.Anything, // bulker options
			).Return("", nil)

			// shared caches, mock bulker, and uploader between test runs had race conditions
			// preventing return of the correct mock data for each call, so we will
			// recreate them within each test run
			c, err := cache.New(config.Cache{NumCounters: 100, MaxCost: 100000})
			require.NoError(t, err)

			u := New(nil, fakeBulk, c, size_ptr(8388608000), time.Hour)

			data := makeUploadRequestDict(map[string]interface{}{
				"file.size": tc.FileSize,
			})

			info, err := u.Begin(t.Context(), []string{}, data)
			assert.NoError(t, err)

			// for anything larger than 1-chunk, check for off-by-ones
			if tc.FinalChunk > 0 {
				mockUploadInfoResult(fakeBulk, info)
				_, prev, err := u.Chunk(t.Context(), info.ID, tc.FinalChunk-1, "")
				assert.NoError(t, err)
				assert.Falsef(t, prev.Last, "penultimate chunk number (%d) should not be marked final", tc.FinalChunk-1)
			}

			mockUploadInfoResult(fakeBulk, info)

			// make sure the final chunk is marked as such
			_, chunk, err := u.Chunk(t.Context(), info.ID, tc.FinalChunk, "")
			assert.NoError(t, err)
			assert.Truef(t, chunk.Last, "chunk number %d should be marked as Last", tc.FinalChunk)
		})
	}
}

func size_ptr(x int) *uint64 {
	y := uint64(x) //nolint:gosec // disable G115
	return &y
}
