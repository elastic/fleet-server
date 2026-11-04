// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package ofrep

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/featureflags/store"
)

// catalogFlagsJSON is the Kibana feature-flag catalog assigned to the kibana app,
// as returned by the management API. It is the definitions a production bulk poll evaluates.
//
//go:embed testdata/catalog_flags.json
var catalogFlagsJSON []byte

const benchSDKKey = "ffsdk-benchmark"

// A steady server context: one targeting key plus the attributes the catalog rules match on.
var benchBody = []byte(`{"context":{"targetingKey":"server-1","organization":{"key":"940234d8f372cc1658c01738aeedf6e1"},"kibana":{"key":"af744095321a495c8e9ef3e6ce14f7d7","offering":"serverless","version":"9.6.0"}}}`)

func catalogHandler(t testing.TB) (http.Handler, int) {
	t.Helper()
	var flags []json.RawMessage
	require.NoError(t, json.Unmarshal(catalogFlagsJSON, &flags))

	sum := sha256.Sum256([]byte(benchSDKKey))
	docs := []store.RawDoc{
		raw("app-kibana", `{"type":"app","app":{"key":"kibana","name":"Kibana"}}`),
		raw("env-production", `{"type":"environment","environment":{"key":"production","name":"Production"}}`),
		raw("cred-production", `{"type":"credential","credential":{"app":"kibana","environment":"production","sdk_key_hash":"`+hex.EncodeToString(sum[:])+`","client_id":"ffcli-benchmark"}}`),
	}
	for i, flag := range flags {
		src := make([]byte, 0, len(flag)+len(`{"type":"flag","flag":}`))
		src = append(src, `{"type":"flag","flag":`...)
		src = append(src, flag...)
		src = append(src, '}')
		docs = append(docs, store.RawDoc{
			ID:      fmt.Sprintf("flag-%02d", i),
			Version: store.DocVersion{SeqNo: 1, PrimaryTerm: 1},
			Source:  src,
		})
	}
	snap := store.NewSnapshot(docs...)
	assigned := snap.FlagsForApp("kibana")
	require.NotEmpty(t, assigned)
	production := 0
	for _, flag := range assigned {
		require.NoError(t, flag.Err, flag.Key)
		// A production credential only evaluates flags configured for that environment.
		if flag.HasEnvironment("production") {
			production++
		}
	}
	require.NotEmpty(t, production)
	src := &source{}
	src.snap.Store(snap)
	return NewHandler(src, Options{}), production
}

func benchRequest(etag string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, PathBulk, bytes.NewReader(benchBody))
	req.Header.Set("Authorization", "Bearer "+benchSDKKey)
	req.Header.Set("Content-Type", "application/json")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	return req
}

func TestCatalogSnapshotEvaluates(t *testing.T) {
	handler, n := catalogHandler(t)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, benchRequest(""))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var body struct {
		Flags []struct {
			Key       string `json:"key"`
			ErrorCode string `json:"errorCode"`
		} `json:"flags"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Len(t, body.Flags, n)
	for _, flag := range body.Flags {
		require.Empty(t, flag.ErrorCode, flag.Key)
	}
	etag := rec.Header().Get("ETag")
	require.NotEmpty(t, etag)

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, benchRequest(etag))
	require.Equal(t, http.StatusNotModified, rec.Code)
}

// BenchmarkOFREPBulk times a full bulk evaluation (the 200 path).
func BenchmarkOFREPBulk(b *testing.B) {
	handler, n := catalogHandler(b)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, benchRequest(""))
	if rec.Code != http.StatusOK {
		b.Fatalf("status %d: %s", rec.Code, rec.Body.Bytes())
	}
	var body struct {
		Flags []json.RawMessage `json:"flags"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		b.Fatal(err)
	}
	if len(body.Flags) != n {
		b.Fatalf("evaluated %d flags, snapshot has %d", len(body.Flags), n)
	}

	b.ReportAllocs()
	for b.Loop() {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, benchRequest(""))
		if rec.Code != http.StatusOK {
			b.Fatalf("status %d", rec.Code)
		}
	}
}

// BenchmarkOFREPBulkNotModified times a poll that sends the previous ETag (the 304 path).
func BenchmarkOFREPBulkNotModified(b *testing.B) {
	handler, _ := catalogHandler(b)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, benchRequest(""))
	etag := rec.Header().Get("ETag")
	if rec.Code != http.StatusOK || etag == "" {
		b.Fatalf("status %d, etag %q", rec.Code, etag)
	}

	b.ReportAllocs()
	for b.Loop() {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, benchRequest(etag))
		if rec.Code != http.StatusNotModified {
			b.Fatalf("status %d", rec.Code)
		}
	}
}
