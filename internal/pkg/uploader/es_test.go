// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package uploader

import (
	"context"
	"fmt"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	itesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestChunkInfoResultsParseCorrectly(t *testing.T) {
	fakeBulk := itesting.NewMockBulk()

	baseID := "abc.xyz"
	sha2 := "ffff"
	size := 3417671

	fakeBulk.On("Search", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&es.ResultT{
		HitsT: es.HitsT{
			Hits: []es.HitT{
				{
					ID:     baseID + ".0",
					Index:  fmt.Sprintf(FileDataIndexPattern, "mysrc"),
					Source: []byte(""),
					Fields: map[string]interface{}{
						"bid":  []interface{}{baseID},
						"last": []interface{}{false},
						"sha2": []interface{}{sha2},
						"size": []interface{}{float64(size)},
					},
				},
				{
					ID:     baseID + ".1",
					Index:  fmt.Sprintf(FileDataIndexPattern, "mysrc"),
					Source: []byte(""),
					Fields: map[string]interface{}{
						"bid":  []interface{}{baseID},
						"last": []interface{}{true},
						"sha2": []interface{}{sha2},
						"size": []interface{}{float64(size)},
					},
				},
			},
		},
	}, nil)

	chunks, err := GetChunkInfos(context.Background(), fakeBulk, baseID)
	assert.NoError(t, err)
	assert.Len(t, chunks, 2)

	assert.Equal(t, baseID, chunks[0].BID)
	assert.False(t, chunks[0].Last)
	assert.Equal(t, sha2, chunks[0].SHA2)
	assert.Equal(t, 0, chunks[0].Pos)
	assert.Equal(t, size, chunks[0].Size)

	assert.Equal(t, baseID, chunks[1].BID)
	assert.True(t, chunks[1].Last)
	assert.Equal(t, sha2, chunks[1].SHA2)
	assert.Equal(t, 1, chunks[1].Pos)
	assert.Equal(t, size, chunks[1].Size)
}
