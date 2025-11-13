// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package delivery

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
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

// cbor decoding and encoding tools can be helpful for examining or changing the test data here
// https://cbor.me/ may be helpful in verifying the shapes of the data

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

	d := New(nil, fakeBulk, nil)

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

	d := New(nil, fakeBulk, nil)

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

	d := New(nil, fakeBulk, nil)

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

	d := New(nil, fakeBulk, nil)

	_, err := d.LocateChunks(context.Background(), zerolog.Logger{}, "afile")
	assert.Error(t, err)
}

func TestSendFile(t *testing.T) {
	buf := bytes.NewBuffer(nil)

	fakeBulk := itesting.NewMockBulk()
	esClient, esMock := mockESClient(t)

	const fileID = "xyz"
	chunks := []file.ChunkInfo{
		{Index: fmt.Sprintf(FileDataIndexPattern, "endpoint"), ID: fileID + ".0"},
	}
	// Chunk data from a tiny PNG, as a full CBOR document
	esMock.Response = sendBodyBytes(hexDecode("bf665f696e64657878212e666c6565742d66696c6564656c69766572792d646174612d656e64706f696e74635f6964654142432e30685f76657273696f6e02675f7365715f6e6f016d5f7072696d6172795f7465726d0165666f756e64f5666669656c6473bf64646174619f586789504e470d0a1a0a0000000d494844520000010000000100010300000066bc3a2500000003504c5445b5d0d0630416ea0000001f494441546881edc1010d000000c2a0f74f6d0e37a00000000000000000be0d210000019a60e1d50000000049454e44ae426082ffffff")) //nolint:bodyclose // nopcloser is used, linter does not see it
	d := New(esClient, fakeBulk, nil)
	err := d.SendFile(context.Background(), zerolog.Logger{}, buf, chunks, fileID)
	require.NoError(t, err)

	// the byte string is the bare PNG file data
	assert.Equal(t, hexDecode("89504e470d0a1a0a0000000d494844520000010000000100010300000066bc3a2500000003504c5445b5d0d0630416ea0000001f494441546881edc1010d000000c2a0f74f6d0e37a00000000000000000be0d210000019a60e1d50000000049454e44ae426082"), buf.Bytes())
}

// sending a file that spans more than 1 chunk
func TestSendFileMultipleChunks(t *testing.T) {
	buf := bytes.NewBuffer(nil)

	fakeBulk := itesting.NewMockBulk()
	esClient, esMock := mockESClient(t)

	const fileID = "xyz"
	chunks := []file.ChunkInfo{
		{Index: fmt.Sprintf(FileDataIndexPattern, "endpoint"), ID: fileID + ".0"},
		{Index: fmt.Sprintf(FileDataIndexPattern, "endpoint"), ID: fileID + ".1"},
	}

	mockChunks := []string{
		"A7665F696E64657878212E666C6565742D66696C6564656C69766572792D646174612D656E64706F696E74635F69646578797A2E30685F76657273696F6E01675F7365715F6E6F016D5F7072696D6172795F7465726D0165666F756E64F5666669656C6473A164646174618142ABCD",
		"A7665F696E64657878212E666C6565742D66696C6564656C69766572792D646174612D656E64706F696E74635F69646578797A2E31685F76657273696F6E01675F7365715F6E6F016D5F7072696D6172795F7465726D0165666F756E64F5666669656C6473A164646174618142EF01",
	}

	esMock.RoundTripFn = func(req *http.Request) (*http.Response, error) {
		if strings.HasSuffix(req.URL.Path, fileID+".0") {
			return sendBodyBytes(hexDecode(mockChunks[0])), nil
		} else if strings.HasSuffix(req.URL.Path, fileID+".1") {
			return sendBodyBytes(hexDecode(mockChunks[1])), nil
		} else {
			return nil, errors.New("invalid chunk index!")
		}
	}

	d := New(esClient, fakeBulk, nil)
	err := d.SendFile(context.Background(), zerolog.Logger{}, buf, chunks, fileID)
	require.NoError(t, err)

	// the collective bytes sent (0xabcd in first chunk, 0xef01 in second)
	assert.Equal(t, hexDecode("abcdef01"), buf.Bytes())
}

// when chunks may be located in different backing indices behind an alias or data stream, they should be fetched from the backing index directly
func TestSendFileMultipleChunksUsesBackingIndex(t *testing.T) {
	buf := bytes.NewBuffer(nil)

	fakeBulk := itesting.NewMockBulk()
	esClient, esMock := mockESClient(t)

	const fileID = "xyz"

	idx1 := fmt.Sprintf(FileDataIndexPattern, "endpoint") + "-0001"
	idx2 := fmt.Sprintf(FileDataIndexPattern, "endpoint") + "-0002"
	chunks := []file.ChunkInfo{
		{Index: idx1, ID: fileID + ".0"},
		{Index: idx2, ID: fileID + ".1"},
	}

	mockData := hexDecode("A7665F696E64657878212E666C6565742D66696C6564656C69766572792D646174612D656E64706F696E74635F69646578797A2E30685F76657273696F6E01675F7365715F6E6F016D5F7072696D6172795F7465726D0165666F756E64F5666669656C6473A164646174618142ABCD")

	esMock.RoundTripFn = func(req *http.Request) (*http.Response, error) {
		parts := strings.Split(req.URL.Path, "/") // ["", ".fleet-filedelivery-data-endpoint-0001", "_doc", "xyz.1"]

		if parts[3] == fileID+".0" {
			assert.Equal(t, idx1, parts[1])
		} else if parts[3] == fileID+".1" {
			assert.Equal(t, idx2, parts[1])
		} else {
			return nil, errors.New("invalid chunk index!")
		}

		return sendBodyBytes(mockData), nil
	}

	d := New(esClient, fakeBulk, nil)
	err := d.SendFile(context.Background(), zerolog.Logger{}, buf, chunks, fileID)
	require.NoError(t, err)
}

func TestSendFileHandlesDisorderedChunks(t *testing.T) {
	buf := bytes.NewBuffer(nil)

	fakeBulk := itesting.NewMockBulk()
	esClient, esMock := mockESClient(t)

	const fileID = "xyz"
	idx := fmt.Sprintf(FileDataIndexPattern, "endpoint") + "-0001"
	sampleDocBody := hexDecode("A7665F696E64657878212E666C6565742D66696C6564656C69766572792D646174612D656E64706F696E74635F69646578797A2E30685F76657273696F6E01675F7365715F6E6F016D5F7072696D6172795F7465726D0165666F756E64F5666669656C6473A164646174618142ABCD")

	chunks := []file.ChunkInfo{
		{Index: idx, ID: fileID + ".20", Pos: 20},
		{Index: idx, ID: fileID + ".21", Pos: 21},
		{Index: idx, ID: fileID + ".22", Pos: 22},
		{Index: idx, ID: fileID + ".9", Pos: 9},
		{Index: idx, ID: fileID + ".10", Pos: 10},
		{Index: idx, ID: fileID + ".11", Pos: 11},
		{Index: idx, ID: fileID + ".12", Pos: 12},
		{Index: idx, ID: fileID + ".13", Pos: 13},
		{Index: idx, ID: fileID + ".14", Pos: 14},
		{Index: idx, ID: fileID + ".15", Pos: 15},
		{Index: idx, ID: fileID + ".16", Pos: 16},
		{Index: idx, ID: fileID + ".17", Pos: 17},
		{Index: idx, ID: fileID + ".18", Pos: 18},
		{Index: idx, ID: fileID + ".19", Pos: 19},
		{Index: idx, ID: fileID + ".0", Pos: 0},
		{Index: idx, ID: fileID + ".1", Pos: 1},
		{Index: idx, ID: fileID + ".2", Pos: 2},
		{Index: idx, ID: fileID + ".3", Pos: 3},
		{Index: idx, ID: fileID + ".4", Pos: 4},
		{Index: idx, ID: fileID + ".5", Pos: 5},
		{Index: idx, ID: fileID + ".6", Pos: 6},
		{Index: idx, ID: fileID + ".7", Pos: 7},
		{Index: idx, ID: fileID + ".8", Pos: 8},
	}

	expectedIdx := 0

	esMock.RoundTripFn = func(req *http.Request) (*http.Response, error) {

		// Parse out the chunk number requested
		parts := strings.Split(req.URL.Path, "/") // ["", ".fleet-filedelivery-data-endpoint-0001", "_doc", "xyz.1"]
		docIdx := strings.TrimPrefix(parts[3], fileID+".")
		docnum, err := strconv.Atoi(docIdx)
		require.NoError(t, err)

		// should be our expected increasing counter
		assert.Equal(t, expectedIdx, docnum)
		expectedIdx += 1

		return sendBodyBytes(sampleDocBody), nil
	}

	d := New(esClient, fakeBulk, nil)
	err := d.SendFile(context.Background(), zerolog.Logger{}, buf, chunks, fileID)
	require.NoError(t, err)
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
		Response: sendBodyString(""), //nolint:bodyclose // nopcloser is used, linter does not see it
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
		Body:       io.NopCloser(body),
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
			"Content-Type":      []string{"application/cbor"},
		},
	}
}

// helper to turn hex data strings into bytes
func hexDecode(s string) []byte {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}
