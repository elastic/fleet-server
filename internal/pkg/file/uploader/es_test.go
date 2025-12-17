// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package uploader

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/file/cbor"
	"github.com/elastic/fleet-server/v7/internal/pkg/testing/esutil"
	"github.com/stretchr/testify/assert"
)

func TestIndexChunkDoesNotUseExpensiveParams(t *testing.T) {
	c, mockTX := esutil.MockESClient(t)
	chunker := cbor.NewChunkWriter(bytes.NewReader([]byte{}), false, "", "", 100)
	called := false
	mockTX.RoundTripFn = func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Path, "/_create") {
			called = true
			refr := req.URL.Query().Get("refresh")
			assert.NotEqual(t, "true", refr, "Chunk Index operation must not use expensive refresh parameter")
		}
		respHeaders := make(http.Header)
		respHeaders.Set("X-Elastic-Product", "Elasticsearch")
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(`{}`)),
			Header:     respHeaders,
		}, nil
	}

	err := IndexChunk(t.Context(), c, chunker, "mypkg", "sampleFileID", 0)
	assert.NoError(t, err)

	assert.True(t, called, "_create API was not called")
}
