// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package api

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/file"
	"github.com/elastic/fleet-server/v7/internal/pkg/file/delivery"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"

	itesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var (
	isFileMetaSearch = mock.MatchedBy(func(idx string) bool {
		return strings.HasPrefix(idx, fmt.Sprintf(delivery.FileHeaderIndexPattern, ""))
	})
	isFileChunkSearch = mock.MatchedBy(func(idx string) bool {
		return strings.HasPrefix(idx, fmt.Sprintf(delivery.FileDataIndexPattern, ""))
	})

	sampleDocBody_ABCD = hexDecode("A7665F696E64657878212E666C6565742D66696C6564656C69766572792D646174612D656E64706F696E74635F69646578797A2E30685F76657273696F6E01675F7365715F6E6F016D5F7072696D6172795F7465726D0165666F756E64F5666669656C6473A164646174618142ABCD")
)

func TestFileDeliveryRouteDisallowedMethods(t *testing.T) {
	hr, _, _, fakebulk := prepareFileDeliveryMock(t)
	rec := httptest.NewRecorder()
	fakebulk.On("Search",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(&es.ResultT{}, nil)

	disallowed := []string{
		http.MethodPost,
		http.MethodDelete,
		http.MethodPut,
	}

	for _, method := range disallowed {
		t.Run("filedelivery"+method, func(t *testing.T) {
			hr.ServeHTTP(rec, httptest.NewRequest(method, "/api/fleet/file/X", nil))
			assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		})
	}
}

func TestFileDeliveryRouteGetMissingFile(t *testing.T) {
	hr, _, _, fakebulk := prepareFileDeliveryMock(t)
	rec := httptest.NewRecorder()
	fakebulk.On("Search",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(&es.ResultT{}, nil)
	hr.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/fleet/file/X", nil))
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// if metadata exists, but no chunks, file should be 404
func TestFileDeliveryNoChunks(t *testing.T) {
	hr, _, _, fakebulk := prepareFileDeliveryMock(t)
	rec := httptest.NewRecorder()

	fakebulk.On("Search", mock.Anything, isFileMetaSearch, mock.Anything, mock.Anything, mock.Anything).Return(
		&es.ResultT{
			HitsT: es.HitsT{
				Hits: []es.HitT{
					{
						ID:      "X",
						SeqNo:   1,
						Version: 1,
						Index:   fmt.Sprintf(delivery.FileHeaderIndexPattern, "endpoint"),
						Source: []byte(`{
							"file": {
								"created": "2023-06-05T15:23:37.499Z",
								"Status": "READY",
								"Updated": "2023-06-05T15:23:37.499Z",
								"name": "test.txt",
								"mime_type": "text/plain",
								"Meta": {
									"target_agents": ["someagent"],
									"action_id": ""
								},
								"size": 256
							}
						}`),
					},
				},
			},
		}, nil,
	).Once()
	fakebulk.On("Search", mock.Anything, isFileChunkSearch, mock.Anything, mock.Anything, mock.Anything).Return(
		&es.ResultT{
			HitsT: es.HitsT{
				Hits: []es.HitT{},
			},
		}, nil,
	)

	hr.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/fleet/file/X", nil))
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestFileDelivery(t *testing.T) {
	hr, _, tx, bulk := prepareFileDeliveryMock(t)
	rec := httptest.NewRecorder()

	bulk.On("Search", mock.Anything, isFileMetaSearch, mock.Anything, mock.Anything, mock.Anything).Return(
		&es.ResultT{
			HitsT: es.HitsT{
				Hits: []es.HitT{{
					ID:      "X",
					SeqNo:   1,
					Version: 1,
					Index:   fmt.Sprintf(delivery.FileHeaderIndexPattern, "endpoint"),
					Source: []byte(`{
						"file": {
							"created": "2023-06-05T15:23:37.499Z",
							"Status": "READY",
							"Updated": "2023-06-05T15:23:37.499Z",
							"name": "somefile",
							"mime_type": "application/octet-stream",
							"Meta": {
								"target_agents": ["someagent"],
								"action_id": ""
							},
							"size": 2
						}
					}`),
				}},
			},
		}, nil,
	)
	bulk.On("Search", mock.Anything, isFileChunkSearch, mock.Anything, mock.Anything, mock.Anything).Return(
		&es.ResultT{
			HitsT: es.HitsT{
				Hits: []es.HitT{
					{
						ID:      "X.0",
						SeqNo:   1,
						Version: 1,
						Index:   fmt.Sprintf(delivery.FileDataIndexPattern, "endpoint"),
						Fields: map[string]any{
							file.FieldBaseID: []any{"X"},
							file.FieldLast:   []any{true},
						},
					},
				},
			},
		}, nil,
	)

	tx.Response = sendBodyBytes(sampleDocBody_ABCD)

	hr.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/fleet/file/X", nil))

	bulk.AssertCalled(t, "Search", mock.Anything, isFileMetaSearch, mock.Anything, mock.Anything, mock.Anything)
	bulk.AssertCalled(t, "Search", mock.Anything, isFileChunkSearch, mock.Anything, mock.Anything, mock.Anything)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, []byte{0xAB, 0xCD}, rec.Body.Bytes())
}

func TestFileDeliveryMultipleChunks(t *testing.T) {
	hr, _, tx, bulk := prepareFileDeliveryMock(t)
	rec := httptest.NewRecorder()

	bulk.On("Search", mock.Anything, isFileMetaSearch, mock.Anything, mock.Anything, mock.Anything).Return(
		&es.ResultT{
			HitsT: es.HitsT{
				Hits: []es.HitT{{
					ID:      "X",
					SeqNo:   1,
					Version: 1,
					Index:   fmt.Sprintf(delivery.FileHeaderIndexPattern, "endpoint"),
					Source: []byte(`{
						"file": {
							"created": "2023-06-05T15:23:37.499Z",
							"Status": "READY",
							"Updated": "2023-06-05T15:23:37.499Z",
							"name": "somefile",
							"mime_type": "application/octet-stream",
							"Meta": {
								"target_agents": ["someagent"],
								"action_id": ""
							},
							"size": 4
						}
					}`),
				}},
			},
		}, nil,
	)
	bulk.On("Search", mock.Anything, isFileChunkSearch, mock.Anything, mock.Anything, mock.Anything).Return(
		&es.ResultT{
			HitsT: es.HitsT{
				Hits: []es.HitT{
					{
						ID:      "X.0",
						SeqNo:   1,
						Version: 1,
						Index:   fmt.Sprintf(delivery.FileDataIndexPattern, "endpoint"),
						Fields: map[string]any{
							file.FieldBaseID: []any{"X"},
						},
					},
					{
						ID:      "X.1",
						SeqNo:   1,
						Version: 1,
						Index:   fmt.Sprintf(delivery.FileDataIndexPattern, "endpoint"),
						Fields: map[string]any{
							file.FieldBaseID: []any{"X"},
							file.FieldLast:   []any{true},
						},
					},
				},
			},
		}, nil,
	)

	mockChunks := []string{
		"A7665F696E64657878212E666C6565742D66696C6564656C69766572792D646174612D656E64706F696E74635F69646578797A2E30685F76657273696F6E01675F7365715F6E6F016D5F7072696D6172795F7465726D0165666F756E64F5666669656C6473A164646174618142ABCD",
		"A7665F696E64657878212E666C6565742D66696C6564656C69766572792D646174612D656E64706F696E74635F69646578797A2E31685F76657273696F6E01675F7365715F6E6F016D5F7072696D6172795F7465726D0165666F756E64F5666669656C6473A164646174618142EF01",
	}

	tx.RoundTripFn = func(req *http.Request) (*http.Response, error) {
		if strings.HasSuffix(req.URL.Path, "X.0") {
			return sendBodyBytes(hexDecode(mockChunks[0])), nil
		} else if strings.HasSuffix(req.URL.Path, "X.1") {
			return sendBodyBytes(hexDecode(mockChunks[1])), nil
		} else {
			return nil, errors.New("invalid chunk index!")
		}
	}

	hr.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/fleet/file/X", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, []byte{0xAB, 0xCD, 0xEF, 0x01}, rec.Body.Bytes())
}

func TestFileDeliverySetsHeaders(t *testing.T) {
	hr, _, tx, bulk := prepareFileDeliveryMock(t)
	rec := httptest.NewRecorder()

	bulk.On("Search", mock.Anything, isFileMetaSearch, mock.Anything, mock.Anything, mock.Anything).Return(
		&es.ResultT{
			HitsT: es.HitsT{
				Hits: []es.HitT{{
					ID:      "X",
					SeqNo:   1,
					Version: 1,
					Index:   fmt.Sprintf(delivery.FileHeaderIndexPattern, "endpoint"),
					Source: []byte(`{
						"file": {
							"created": "2023-06-05T15:23:37.499Z",
							"Status": "READY",
							"Updated": "2023-06-05T15:23:37.499Z",
							"name": "test.csv",
							"mime_type": "text/csv",
							"Meta": {
								"target_agents": ["someagent"],
								"action_id": ""
							},
							"size": 4
						}
					}`),
				}},
			},
		}, nil,
	)
	bulk.On("Search", mock.Anything, isFileChunkSearch, mock.Anything, mock.Anything, mock.Anything).Return(
		&es.ResultT{
			HitsT: es.HitsT{
				Hits: []es.HitT{
					{
						ID:      "X.0",
						SeqNo:   1,
						Version: 1,
						Index:   fmt.Sprintf(delivery.FileDataIndexPattern, "endpoint"),
						Fields: map[string]any{
							file.FieldBaseID: []any{"X"},
							file.FieldLast:   []any{true},
						},
					},
				},
			},
		}, nil,
	)
	tx.Response = sendBodyBytes(sampleDocBody_ABCD)

	hr.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/fleet/file/X", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/csv", rec.Header().Get("Content-Type"))
	assert.Equal(t, "4", rec.Header().Get("Content-Length"))
	assert.Empty(t, rec.Header().Get("X-File-SHA2"))
	assert.Equal(t, "bytes", rec.Header().Get("Accept-Ranges"))
}

func TestFileDeliverySetsHashWhenPresent(t *testing.T) {
	hr, _, tx, bulk := prepareFileDeliveryMock(t)
	rec := httptest.NewRecorder()

	bulk.On("Search", mock.Anything, isFileMetaSearch, mock.Anything, mock.Anything, mock.Anything).Return(
		&es.ResultT{
			HitsT: es.HitsT{
				Hits: []es.HitT{{
					ID:      "X",
					SeqNo:   1,
					Version: 1,
					Index:   fmt.Sprintf(delivery.FileHeaderIndexPattern, "endpoint"),
					Source: []byte(`{
						"file": {
							"created": "2023-06-05T15:23:37.499Z",
							"Status": "READY",
							"Updated": "2023-06-05T15:23:37.499Z",
							"name": "test.csv",
							"mime_type": "text/csv",
							"Meta": {
								"target_agents": ["someagent"],
								"action_id": ""
							},
							"size": 4,
							"hash": {
								"sha256": "deadbeef"
							}
						}
					}`),
				}},
			},
		}, nil,
	)
	bulk.On("Search", mock.Anything, isFileChunkSearch, mock.Anything, mock.Anything, mock.Anything).Return(
		&es.ResultT{
			HitsT: es.HitsT{
				Hits: []es.HitT{
					{
						ID:      "X.0",
						SeqNo:   1,
						Version: 1,
						Index:   fmt.Sprintf(delivery.FileDataIndexPattern, "endpoint"),
						Fields: map[string]any{
							file.FieldBaseID: []any{"X"},
							file.FieldLast:   []any{true},
						},
					},
				},
			},
		}, nil,
	)
	tx.Response = sendBodyBytes(sampleDocBody_ABCD)

	hr.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/fleet/file/X", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "deadbeef", rec.Header().Get("X-File-SHA2"))
}

func TestRangeParsing(t *testing.T) {

	cases := []struct {
		header            string
		expectedStartByte int64
		expectedLength    int64
		fileSize          int64
	}{
		{"bytes=0-209", 0, 210, 600},
		{"bytes=50-499", 50, 450, 600},
		{"bytes=-100", 500, 100, 600},
		{"bytes=400-", 400, 200, 600},
	}

	for _, tc := range cases {
		t.Run(tc.header, func(t *testing.T) {
			ranges, err := parseRange(tc.header, tc.fileSize)
			require.NoError(t, err)
			assert.Equal(t, 1, len(ranges))
			assert.Equal(t, httpRange{tc.expectedStartByte, tc.expectedLength}, ranges[0])
		})
	}
}

func TestRangeParsingErrs(t *testing.T) {

	cases := []string{
		"bytes=100-40",
		"bytes=40",
		"bytes 9-99",
		"400-500",
		"bytes=start-end",
		"bytes=--400",
		"bytes=-100-400",
		"bytes=20--100",
	}

	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			_, err := parseRange(tc, 1024)
			assert.Error(t, err)
		})
	}
}

func TestFileDeliveryRangeSupport(t *testing.T) {
	hr, _, tx, bulk := prepareFileDeliveryMock(t)

	mockChunkSize := 100
	mockFileSize := 600

	mockBodyBytes := mockChunkedFile(tx, bulk, int64(mockChunkSize), int64(mockFileSize), "X")

	// Testing behaviors described in https://datatracker.ietf.org/doc/html/rfc9110#section-14.1.2
	cases := []struct {
		rangeReq      string // byte string as requested
		expectedStart int
		expectedEnd   int
	}{
		{"10-209", 10, 209},
		{"103-443", 103, 443},
		{"0-306", 0, 306},
		{"7-30", 7, 30},                                // range within a single chunk
		{"405-", 405, mockFileSize - 1},                // open-ended, goes to EOF
		{"-150", mockFileSize - 150, mockFileSize - 1}, // last N bytes format
		{"400-900", 400, mockFileSize - 1},             // if larger than end, server corrects it to be the file-end
		{"-900", 0, mockFileSize - 1},                  // suffix spec greater than file size self-corrects and gives the whole file
	}

	for _, tc := range cases {
		t.Run(tc.rangeReq, func(t *testing.T) {
			rec := httptest.NewRecorder()

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/fleet/file/X", nil)
			req.Header.Set("Range", "bytes="+tc.rangeReq)

			hr.ServeHTTP(rec, req)
			require.Equal(t, http.StatusPartialContent, rec.Code)
			assert.Equal(t, fmt.Sprintf("bytes %d-%d/%d", tc.expectedStart, tc.expectedEnd, mockFileSize), rec.Header().Get("Content-Range"))
			assert.Equal(t, strconv.Itoa(tc.expectedEnd-tc.expectedStart+1), rec.Header().Get("Content-Length"))
			assert.Equal(t, tc.expectedEnd-tc.expectedStart+1, rec.Body.Len())
			assert.Equal(t, mockBodyBytes[tc.expectedStart:tc.expectedEnd+1], rec.Body.Bytes())

		})
	}

}

func TestFileDeliveryInvalidRangeReq(t *testing.T) {
	hr, _, tx, bulk := prepareFileDeliveryMock(t)

	mockChunkSize := 64
	mockFileSize := 450

	mockBodyBytes := mockChunkedFile(tx, bulk, int64(mockChunkSize), int64(mockFileSize), "X")
	_ = mockBodyBytes

	// invalid ranges
	cases := []struct {
		rangeReq         string // byte string as requested
		expectedHTTPCode int
	}{
		{"900-1200", http.StatusRequestedRangeNotSatisfiable},
		{"100-20", http.StatusRequestedRangeNotSatisfiable},
	}

	for _, tc := range cases {
		t.Run(tc.rangeReq, func(t *testing.T) {
			rec := httptest.NewRecorder()

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/fleet/file/X", nil)
			req.Header.Set("Range", "bytes="+tc.rangeReq)

			hr.ServeHTTP(rec, req)
			require.Equal(t, tc.expectedHTTPCode, rec.Code)

		})
	}
}

func TestFileLibraryDeliveryStopsEmptyClients(t *testing.T) {
	hr, _, _, _ := prepareFileDeliveryMock(t)
	rec := httptest.NewRecorder()

	req := httptest.NewRequest(http.MethodGet, "/api/fleet/file/X?source=foo", nil)
	req.Header.Del(HTTPProductOriginHeader)
	hr.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestFileLibraryDeliveryStopsInvalidClients(t *testing.T) {
	hr, _, _, _ := prepareFileDeliveryMock(t)
	rec := httptest.NewRecorder()

	req := httptest.NewRequest(http.MethodGet, "/api/fleet/file/X?source=foo", nil)
	req.Header.Add(HTTPProductOriginHeader, "bar")
	hr.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestFileLibraryDeliveryAllowsValidClients(t *testing.T) {
	hr, _, tx, bulk := prepareFileDeliveryMock(t)
	rec := httptest.NewRecorder()

	libName := "foolib"
	dataIndex := fmt.Sprintf(delivery.LibraryFileDataIndexPattern, "endpoint", libName)

	bulk.On("Read", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
		[]byte(`{}`), nil,
	)
	bulk.On("Search", mock.Anything, dataIndex, mock.Anything, mock.Anything, mock.Anything).Return(
		&es.ResultT{
			HitsT: es.HitsT{
				Hits: []es.HitT{
					{
						ID:      "X.0",
						SeqNo:   1,
						Version: 1,
						Index:   fmt.Sprintf(delivery.LibraryFileDataIndexPattern, "endpoint", libName),
						Fields: map[string]any{
							file.FieldBaseID: []any{"X"},
							file.FieldLast:   []any{true},
						},
					},
				},
			},
		}, nil,
	)
	tx.Response = sendBodyBytes(sampleDocBody_ABCD)

	req := httptest.NewRequest(http.MethodGet, "/api/fleet/file/X?source="+libName, nil)
	req.Header.Set(HTTPProductOriginHeader, "endpoint-security")
	hr.ServeHTTP(rec, req)

	bulk.AssertCalled(t, "Read", mock.Anything, mock.Anything, mock.Anything, mock.Anything)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestFileLibraryDelivery(t *testing.T) {
	hr, _, tx, bulk := prepareFileDeliveryMock(t)
	rec := httptest.NewRecorder()

	libName := "script"
	dataIndex := fmt.Sprintf(delivery.LibraryFileDataIndexPattern, "endpoint", libName)

	bulk.On("Read", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
		[]byte(`{
				"file": {
					"created": "2023-06-05T15:23:37.499Z",
					"Status": "READY",
					"Updated": "2023-06-05T15:23:37.499Z",
					"name": "somefile.csv",
					"mime_type": "text/csv",
					"size": 4,
					"hash": {
						"sha256": "deadbeef"
					}
				}
			}`), nil,
	)
	bulk.On("Search", mock.Anything, dataIndex, mock.Anything, mock.Anything, mock.Anything).Return(
		&es.ResultT{
			HitsT: es.HitsT{
				Hits: []es.HitT{
					{
						ID:      "X.0",
						SeqNo:   1,
						Version: 1,
						Index:   fmt.Sprintf(delivery.LibraryFileDataIndexPattern, "endpoint", libName),
						Fields: map[string]any{
							file.FieldBaseID: []any{"X"},
							file.FieldLast:   []any{true},
						},
					},
				},
			},
		}, nil,
	)
	tx.Response = sendBodyBytes(sampleDocBody_ABCD)

	req := httptest.NewRequest(http.MethodGet, "/api/fleet/file/X?source="+libName, nil)
	req.Header.Set(HTTPProductOriginHeader, "endpoint-security")
	hr.ServeHTTP(rec, req)

	bulk.AssertCalled(t, "Read", mock.Anything, mock.Anything, mock.Anything, mock.Anything)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, []byte{0xAB, 0xCD}, rec.Body.Bytes())
	assert.Equal(t, "text/csv", rec.Header().Get("Content-Type"))
	assert.Equal(t, "4", rec.Header().Get("Content-Length"))
	assert.Equal(t, "deadbeef", rec.Header().Get("X-File-SHA2"))
}

/*
	Helpers and mocks
*/

// prepareUploaderMock sets up common dependencies and registers upload routes to a returned router
func prepareFileDeliveryMock(t *testing.T) (http.Handler, apiServer, *MockTransport, *itesting.MockBulk) {
	// chunk index operations skip the bulker in order to send binary docs directly
	// so a mock *elasticsearch.Client needs to be be prepared
	mockES, tx := mockESClient(t)

	fakebulk := itesting.NewMockBulk()
	fakebulk.On("Client",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(mockES, nil)

	c, err := cache.New(config.Cache{NumCounters: 100, MaxCost: 100000})
	require.NoError(t, err)

	si := apiServer{
		ft: &FileDeliveryT{
			bulker:    fakebulk,
			cache:     c,
			deliverer: delivery.New(mockES, fakebulk, nil),
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
		},
	}

	return Handler(&si), si, tx, fakebulk
}

func mockChunkedFile(tx *MockTransport, bulk *itesting.MockBulk, mockChunkSize int64, mockFileSize int64, fileID string) []byte {
	mockBodyBytes := make([]byte, mockFileSize)
	j := 0
	for i := range mockFileSize {
		mockBodyBytes[i] = byte(j)
		j += 1
		if j > 255 {
			j = 0
		}
	}
	chunkHits := make([]es.HitT, int(math.Ceil(float64(mockFileSize)/float64(mockChunkSize))))
	for i := range chunkHits {
		chunkHits[i] = es.HitT{
			ID:      fmt.Sprintf("%s.%d", fileID, i),
			SeqNo:   1,
			Version: 1,
			Index:   fmt.Sprintf(delivery.FileDataIndexPattern, "endpoint"),
			Fields: map[string]any{
				file.FieldBaseID: []any{fileID},
			},
		}
		if i == len(chunkHits)-1 {
			chunkHits[i].Fields[file.FieldLast] = []any{true}
		}
	}

	bulk.On("Search", mock.Anything, isFileMetaSearch, mock.Anything, mock.Anything, mock.Anything).Return(
		&es.ResultT{
			HitsT: es.HitsT{
				Hits: []es.HitT{{
					ID:      fileID,
					SeqNo:   1,
					Version: 1,
					Index:   fmt.Sprintf(delivery.FileHeaderIndexPattern, "endpoint"),
					Source: fmt.Appendf(nil, `{
						"file": {
							"created": "2023-06-05T15:23:37.499Z",
							"Status": "READY",
							"Updated": "2023-06-05T15:23:37.499Z",
							"name": "somefile",
							"mime_type": "application/octet-stream",
							"Meta": {
								"target_agents": ["someagent"],
								"action_id": ""
							},
							"size": %d,
							"ChunkSize": %d
						}
					}`, mockFileSize, mockChunkSize),
				}},
			},
		}, nil,
	)
	bulk.On("Search", mock.Anything, isFileChunkSearch, mock.Anything, mock.Anything, mock.Anything).Return(
		&es.ResultT{
			HitsT: es.HitsT{
				Hits: chunkHits,
			},
		}, nil,
	)

	mockChunks := make([][]byte, len(chunkHits))
	for i := range chunkHits {
		sliceTo := int64(math.Min(float64((int64(i)+1)*mockChunkSize), float64(mockFileSize)))
		mockChunks[i] = mockChunkCBOR(fmt.Sprintf("%s.%d", fileID, i), mockBodyBytes[int64(i)*mockChunkSize:sliceTo])
	}

	tx.RoundTripFn = func(req *http.Request) (*http.Response, error) {
		// Parse out the chunk number requested
		parts := strings.Split(req.URL.Path, "/") // ["", ".fleet-filedelivery-data-endpoint-0001", "_doc", "xyz.1"]
		docIdx := strings.TrimPrefix(parts[3], fileID+".")
		docnum, err := strconv.Atoi(docIdx)
		if err != nil {
			return nil, err
		}

		if docnum < 0 || docnum > len(mockChunks)-1 {
			return nil, errors.New("invalid chunk")
		}
		return sendBodyBytes(mockChunks[docnum]), nil
	}

	return mockBodyBytes
}

func hexDecode(s string) []byte {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

func mockChunkCBOR(docid string, data []byte) []byte {
	dlen := make([]byte, 4)
	binary.BigEndian.PutUint32(dlen, uint32(len(data)))
	return hexDecode(fmt.Sprintf("A7665F696E64657878212E666C6565742D66696C6564656C69766572792D646174612D656E64706F696E74635F6964%02X%02X685F76657273696F6E01675F7365715F6E6F016D5F7072696D6172795F7465726D0165666F756E64F5666669656C6473A16464617461815A%02X%02X", len(docid)+0x60, docid, dlen, data))
}
