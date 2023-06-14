// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package delivery

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/file"
	itesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	"github.com/elastic/go-elasticsearch/v8"
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

func TestSendFile(t *testing.T) {
	buf := bytes.NewBuffer(nil)

	fakeBulk := itesting.NewMockBulk()
	esClient, esMock := mockESClient(t)

	fileID := "xyz"
	chunks := []file.ChunkInfo{
		{Index: fmt.Sprintf(FileDataIndexPattern, "endpoint"), ID: fileID + ".0"},
	}
	// Chunk data from a tiny PNG, as a full CBOR document
	esMock.Response.Body = ioutil.NopCloser(bytes.NewReader(hexDecode("bf665f696e64657878212e666c6565742d66696c6564656c69766572792d646174612d656e64706f696e74635f6964654142432e30685f76657273696f6e02675f7365715f6e6f016d5f7072696d6172795f7465726d0165666f756e64f5666669656c6473bf64646174619f586789504e470d0a1a0a0000000d494844520000010000000100010300000066bc3a2500000003504c5445b5d0d0630416ea0000001f494441546881edc1010d000000c2a0f74f6d0e37a00000000000000000be0d210000019a60e1d50000000049454e44ae426082ffffff")))

	d := New(esClient, fakeBulk, -1)
	err := d.SendFile(context.Background(), zerolog.Logger{}, buf, chunks, fileID)
	require.NoError(t, err)

	// the byte string is the bare PNG file data
	assert.Equal(t, hexDecode("89504e470d0a1a0a0000000d494844520000010000000100010300000066bc3a2500000003504c5445b5d0d0630416ea0000001f494441546881edc1010d000000c2a0f74f6d0e37a00000000000000000be0d210000019a60e1d50000000049454e44ae426082"), buf.Bytes())
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
		Response: &http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(strings.NewReader(`{}`)),
			Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		},
	}

	mocktrans.RoundTripFn = func(req *http.Request) (*http.Response, error) { return mocktrans.Response, nil }
	client, err := elasticsearch.NewClient(elasticsearch.Config{
		Transport: &mocktrans,
	})
	require.NoError(t, err)
	return client, &mocktrans
}

// helper to turn hex data strings into bytes
func hexDecode(s string) []byte {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}
