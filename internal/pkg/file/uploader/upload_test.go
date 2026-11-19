// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

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

// Dotted paths into the upload request, as accepted by makeUploadRequestDict.
const (
	testKeyFileName = fileKey + ".name"
	testKeyFileSize = fileKey + "." + fieldSize
)

// convenience function for making a typical file request structure
// with defaults when specific values are not checked or required
func makeUploadRequestDict(input map[string]interface{}) JSDict {
	// defaults
	d := JSDict{
<<<<<<< HEAD
		"file": map[string]interface{}{
=======
		fileKey: map[string]any{
>>>>>>> a937df3 (chore(deps): update Go to 1.27.4 (#8247))
			"name":      "foo.png",
			"mime_type": "image/png",
			fieldSize:   1024,
		},
		fieldActionID: "123",
		fieldAgentID:  "456",
		fieldSource:   "agent",
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
<<<<<<< HEAD
	data := makeUploadRequestDict(map[string]interface{}{
		"action_id": action,
		"agent_id":  agent,
		"src":       src,
		"file.size": size,
=======
	data := makeUploadRequestDict(map[string]any{
		fieldActionID:   action,
		fieldAgentID:    agent,
		fieldSource:     src,
		testKeyFileSize: size,
>>>>>>> a937df3 (chore(deps): update Go to 1.27.4 (#8247))
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
	u := New(nil, fakeBulk, c, int64(size), time.Hour)
	info, err := u.Begin(context.Background(), []string{}, data)
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

<<<<<<< HEAD
	data := makeUploadRequestDict(map[string]interface{}{
		"action_id": action,
		"agent_id":  agent,
		"src":       src,
		"file.name": name,
		"file.size": size,
=======
	data := makeUploadRequestDict(map[string]any{
		fieldActionID:   action,
		fieldAgentID:    agent,
		fieldSource:     src,
		testKeyFileName: name,
		testKeyFileSize: size,
>>>>>>> a937df3 (chore(deps): update Go to 1.27.4 (#8247))
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
	u := New(nil, fakeBulk, c, int64(size), time.Hour)
	_, err = u.Begin(context.Background(), []string{}, data)
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
	u := New(nil, fakeBulk, c, file.MaxChunkSize*3000, time.Hour)

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
<<<<<<< HEAD
			data := makeUploadRequestDict(map[string]interface{}{
				"file.size": tc.FileSize,
=======
			data := makeUploadRequestDict(map[string]any{
				testKeyFileSize: tc.FileSize,
>>>>>>> a937df3 (chore(deps): update Go to 1.27.4 (#8247))
			})
			info, err := u.Begin(context.Background(), []string{}, data)
			assert.NoError(t, err)
			assert.Equal(t, tc.ExpectedCount, info.Count)
		})
	}
}

func TestUploadBeginMaxFileSize(t *testing.T) {
	tests := []struct {
		UploadSizeLimit int64
		FileSize        int64
		ShouldError     bool
		Name            string
	}{
		{500, 800, true, "800 is too large"},
		{800, 500, false, "file within limits"},
		{1024, 1023, false, "1-less than limit"},
		{1024, 1024, false, "file is exactly limit"},
		{1024, 1025, true, "file is 1 over limit"},
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
<<<<<<< HEAD
			data := makeUploadRequestDict(map[string]interface{}{
				"file.size": tc.FileSize,
=======
			data := makeUploadRequestDict(map[string]any{
				testKeyFileSize: tc.FileSize,
>>>>>>> a937df3 (chore(deps): update Go to 1.27.4 (#8247))
			})
			_, err := u.Begin(context.Background(), []string{}, data)
			if tc.ShouldError {
				assert.ErrorIs(t, err, ErrFileSizeTooLarge)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestUploadRejectsMissingRequiredFields(t *testing.T) {

	tests := []string{
		testKeyFileName,
		"file.mime_type",
		testKeyFileSize,
		fieldActionID,
		fieldAgentID,
		fieldSource,
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

	u := New(nil, fakeBulk, c, 2048, time.Hour)

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

			_, err = u.Begin(context.Background(), []string{}, data)
			assert.Errorf(t, err, "%s is a required field and should error if not provided", field)
		})

	}

}

func mockUploadInfoResult(bulker *itesting.MockBulk, info file.Info) {

	// convert info into how it's stored/returned in ES
<<<<<<< HEAD
	out, _ := json.Marshal(map[string]interface{}{
		"action_id": info.ActionID,
		"agent_id":  info.AgentID,
		"src":       info.Source,
		"file": map[string]interface{}{
			"size":      info.Total,
			"ChunkSize": info.ChunkSize,
			"Status":    info.Status,
=======
	out, _ := json.Marshal(map[string]any{
		fieldActionID: info.ActionID,
		fieldAgentID:  info.AgentID,
		fieldSource:   info.Source,
		fileKey: map[string]any{
			fieldSize:      info.Total,
			fieldChunkSize: info.ChunkSize,
			fieldStatus:    info.Status,
>>>>>>> a937df3 (chore(deps): update Go to 1.27.4 (#8247))
		},
		file.FieldUploadID: info.ID,
		fieldUploadStart:   info.Start.UnixMilli(),
	})

	bulker.On("Search",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(&es.ResultT{
		Hits: []es.HitT{
			{
				ID:     info.DocID,
				Source: out,
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
		{file.MaxChunkSize + 1, 1, "ChunkSize+1 bytes second chunk is final"},
		{file.MaxChunkSize * 2.5, 2, "2.5x chunk size"},
		{7534559605, 1796, "7.5Gb file last chunk is final"},
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

			u := New(nil, fakeBulk, c, 8388608000, time.Hour)

<<<<<<< HEAD
			data := makeUploadRequestDict(map[string]interface{}{
				"file.size": tc.FileSize,
=======
			data := makeUploadRequestDict(map[string]any{
				testKeyFileSize: tc.FileSize,
>>>>>>> a937df3 (chore(deps): update Go to 1.27.4 (#8247))
			})

			info, err := u.Begin(context.Background(), []string{}, data)
			assert.NoError(t, err)

			// for anything larger than 1-chunk, check for off-by-ones
			if tc.FinalChunk > 0 {
				mockUploadInfoResult(fakeBulk, info)
				_, prev, err := u.Chunk(context.Background(), info.ID, tc.FinalChunk-1, "")
				assert.NoError(t, err)
				assert.Falsef(t, prev.Last, "penultimate chunk number (%d) should not be marked final", tc.FinalChunk-1)
			}

			mockUploadInfoResult(fakeBulk, info)

			// make sure the final chunk is marked as such
			_, chunk, err := u.Chunk(context.Background(), info.ID, tc.FinalChunk, "")
			assert.NoError(t, err)
			assert.Truef(t, chunk.Last, "chunk number %d should be marked as Last", tc.FinalChunk)
		})
	}
}
