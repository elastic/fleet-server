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

	itesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	"github.com/elastic/fleet-server/v7/internal/pkg/uploader/upload"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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
		".fleet-files-"+src, // index
		action+"."+agent,    // document ID
		mock.Anything,       // ES document
		mock.Anything,       // bulker options
	).Return("", nil)

	u := New(nil, fakeBulk, int64(size), time.Hour)
	info, err := u.Begin(context.Background(), data)
	assert.NoError(t, err)

	assert.Equal(t, int64(size), info.Total)
	assert.Equal(t, action, info.ActionID)
	assert.Equal(t, agent, info.AgentID)
	assert.Equal(t, src, info.Source)
	assert.Equal(t, upload.StatusAwaiting, info.Status)
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
		".fleet-files-"+src, // index
		action+"."+agent,    // document ID
		mock.Anything,       // ES document
		mock.Anything,       // bulker options
	).Return("", nil)

	u := New(nil, fakeBulk, int64(size), time.Hour)
	_, err := u.Begin(context.Background(), data)
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
		{MaxChunkSize, 1, "Precisely 1 chunk size bytes should fit in 1 chunk"},
		{MaxChunkSize + 1, 2, "ChunkSize+1 bytes takes 2 chunks"},
		{MaxChunkSize * 3.5, 4, "3.5x chunk size fits in 4 chunks due to remainder"},
		{7534559605, 1797, "7.5Gb file"},
	}

	u := New(nil, fakeBulk, MaxChunkSize*3000, time.Hour)

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			data := makeUploadRequestDict(map[string]interface{}{
				"file.size": tc.FileSize,
			})
			info, err := u.Begin(context.Background(), data)
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

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			u := New(nil, fakeBulk, tc.UploadSizeLimit, time.Hour)
			data := makeUploadRequestDict(map[string]interface{}{
				"file.size": tc.FileSize,
			})
			_, err := u.Begin(context.Background(), data)
			if tc.ShouldError {
				assert.ErrorIs(t, err, ErrFileSizeTooLarge)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

/*
func TestUploadRejectsMissingRequiredFields(t *testing.T) {
	data := makeUploadRequestDict()

	u := New(nil, nil, 1024, time.Hour)
	info, err := u.Begin(context.Background(), data)
	assert.Error(t, err)

}


*/

/*

func TestChunkMarksFinal(t *testing.T) {
	tests := []struct {
		FileSize   int64
		FinalChunk int
		Name       string
	}{
		{10, 0, "Small file only chunk is final"},
		{MaxChunkSize, 0, "1 chunksize only chunk is final"},
		{MaxChunkSize + 1, 1, "ChunkSize+1 bytes takes 2 chunks"},
		{MaxChunkSize * 2.5, 2, "2.5x chunk size"},
		{7534559605, 1796, "7.5Gb file"},
	}

	u := New(8388608000, len(tests), 4)

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			info, err := u.Begin(tc.FileSize, "", "")
			assert.NoError(t, err)

			if tc.FinalChunk > 0 {
				prev, err := u.Chunk(info.ID, tc.FinalChunk-1)
				assert.NoError(t, err)
				assert.Falsef(t, prev.Final, "previous chunk ID before last should not be marked final")
				prev.Token.Release()
			}

			chunk, err := u.Chunk(info.ID, tc.FinalChunk)
			assert.NoError(t, err)
			assert.True(t, chunk.Final)
			chunk.Token.Release()
		})
	}
}


*/
