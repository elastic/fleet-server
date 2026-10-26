// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package esclient

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/elastic/go-elasticsearch/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		w.Header().Set("Content-Type", "application/json")
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	es, err := elasticsearch.NewClient(elasticsearch.Config{Addresses: []string{srv.URL}})
	require.NoError(t, err)
	return New(es)
}

func TestSearch(t *testing.T) {
	var gotPath, gotBody string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_, _ = w.Write([]byte(`{"hits":{"hits":[]}}`))
	})
	data, err := c.Search(t.Context(), ".feature-flags-definitions", []byte(`{"size":0}`))
	require.NoError(t, err)
	assert.JSONEq(t, `{"hits":{"hits":[]}}`, string(data))
	assert.Equal(t, "/.feature-flags-definitions/_search", gotPath)
	assert.JSONEq(t, `{"size":0}`, gotBody)
}

func TestSearchIndexNotFound(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"type":"index_not_found_exception","reason":"no such index"},"status":404}`))
	})
	_, err := c.Search(t.Context(), "missing", []byte(`{}`))
	require.ErrorIs(t, err, ErrIndexNotFound)
}

func TestSearchOtherError(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"type":"security_exception","reason":"unauthorized"},"status":403}`))
	})
	_, err := c.Search(t.Context(), "idx", []byte(`{}`))
	var respErr *ResponseError
	require.ErrorAs(t, err, &respErr)
	assert.Equal(t, http.StatusForbidden, respErr.Status)
	assert.Equal(t, "security_exception", respErr.Type)
	assert.NotErrorIs(t, err, ErrIndexNotFound)
}

func TestBulk(t *testing.T) {
	var gotPath string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"errors":false,"items":[]}`))
	})
	data, err := c.Bulk(t.Context(), []byte("{\"update\":{}}\n{}\n"))
	require.NoError(t, err)
	assert.JSONEq(t, `{"errors":false,"items":[]}`, string(data))
	assert.Equal(t, "/_bulk", gotPath)
}

func TestParseError(t *testing.T) {
	err := ParseError(500, []byte(`not json`))
	var respErr *ResponseError
	require.ErrorAs(t, err, &respErr)
	assert.Equal(t, "not json", respErr.Reason)

	err = ParseError(400, []byte(`{"error":"plain message"}`))
	require.ErrorAs(t, err, &respErr)
	assert.Equal(t, `"plain message"`, respErr.Reason)
}
