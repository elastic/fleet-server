// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package delivery

import (
	"context"
	"fmt"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	itesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestFindFile(t *testing.T) {
	fakeBulk := itesting.NewMockBulk()

	agentID := "abcagent"
	fileID := "xyzfile"

	fakeBulk.Mock.On("Search",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(&es.ResultT{
		HitsT: es.HitsT{
			Hits: []es.HitT{
				{
					ID:    fileID,
					Index: fmt.Sprintf(FileHeaderIndexPattern, "endpoint"),
					Source: []byte(`{
						"file": {
							"created": "2023-06-05T15:23:37.499Z",
							"Status": "READY",
							"Updated": "2023-06-05T15:23:37.499Z",
							"name": "test.txt",
							"mime_type": "text/plain",
							"Meta": {
								"target_agents": ["` + agentID + `"],
								"action_id": ""
							},
							"size": 256,
							"hash": {
								"sha256": "b94276997f744bab637c2e937bb349947bc2c3b6c6397feb5b252c6928c7799b"
							}
						}
					}`),
				},
			},
		},
	}, nil)

	d := New(nil, fakeBulk, -1)

	info, err := d.FindFileForAgent(context.Background(), fileID, agentID)
	require.NoError(t, err)

	assert.NotNil(t, info.File.Hash)
	assert.Equal(t, "READY", info.File.Status)
}

func TestFindFileHandlesNoResults(t *testing.T) {
	fakeBulk := itesting.NewMockBulk()

	// handles case where ES does not return an error, simply no results
	fakeBulk.Mock.On("Search",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(&es.ResultT{
		HitsT: es.HitsT{
			Hits: []es.HitT{},
		},
	}, nil)

	d := New(nil, fakeBulk, -1)

	_, err := d.FindFileForAgent(context.Background(), "somefile", "anyagent")
	assert.ErrorIs(t, ErrNoFile, err)
}

func TestLocateChunks(t *testing.T) {
	fakeBulk := itesting.NewMockBulk()

	baseID := "somefile"

	fakeBulk.Mock.On("Search",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(&es.ResultT{
		HitsT: es.HitsT{
			Hits: []es.HitT{
				{
					ID:     baseID + ".0",
					Index:  "",
					Source: []byte(""),
					Fields: map[string]interface{}{
						"bid": []interface{}{baseID},
					},
				},
				{
					ID:     baseID + ".1",
					Index:  "",
					Source: []byte(""),
					Fields: map[string]interface{}{
						"bid":  []interface{}{baseID},
						"last": []interface{}{true},
					},
				},
			},
		},
	}, nil)

	d := New(nil, fakeBulk, -1)

	chunks, err := d.LocateChunks(context.Background(), zerolog.Logger{}, baseID)
	require.NoError(t, err)

	assert.Len(t, chunks, 2)
}

func TestLocateChunksEmpty(t *testing.T) {
	fakeBulk := itesting.NewMockBulk()

	fakeBulk.Mock.On("Search",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(&es.ResultT{
		HitsT: es.HitsT{
			Hits: []es.HitT{},
		},
	}, nil)

	d := New(nil, fakeBulk, -1)

	_, err := d.LocateChunks(context.Background(), zerolog.Logger{}, "afile")
	assert.Error(t, err)
}
