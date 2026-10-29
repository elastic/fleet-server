// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package ofrep

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/featureflags/eval"
	"github.com/elastic/fleet-server/v7/internal/pkg/featureflags/store"
)

const (
	sdkKey   = "ffsdk-secret"
	clientID = "ffcli-public"
)

type source struct {
	snap atomic.Pointer[store.Snapshot]
}

func (s *source) Load() *store.Snapshot { return s.snap.Load() }

type recorder struct {
	mu   sync.Mutex
	seen []eval.Context
}

func (r *recorder) Observe(_, _ string, ctx eval.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, ctx)
}

func hashKey(k string) string {
	sum := sha256.Sum256([]byte(k))
	return hex.EncodeToString(sum[:])
}

func raw(id, src string) store.RawDoc {
	return store.RawDoc{ID: id, Version: store.DocVersion{SeqNo: 1, PrimaryTerm: 1}, Source: json.RawMessage(src)}
}

func testSnapshot(extra ...store.RawDoc) *store.Snapshot {
	docs := []store.RawDoc{
		raw("cred-prod", `{"type": "credential", "credential": {"app": "kibana", "environment": "production",
		  "sdk_key_hash": "`+hashKey(sdkKey)+`", "client_id": "`+clientID+`"}}`),
		raw("cred-qa", `{"type": "credential", "credential": {"app": "kibana", "environment": "qa", "sdk_key_hash": "`+hashKey("qa-key")+`"}}`),
		raw("cred-other", `{"type": "credential", "credential": {"app": "other", "environment": "production", "sdk_key_hash": "`+hashKey("other-key")+`"}}`),
		raw("flag-1", `{"type": "flag", "flag": {"key": "b.targeted", "variations": [true, false], "apps": ["kibana"],
		  "environments": {"production": {"default": false, "rules": [
		    {"type": "match", "attribute": "kibana.offering", "values": ["serverless"], "return": true},
		    {"type": "percentage", "per_attribute": "targetingKey", "percentages": {"true": 0, "false": 100}}]}}}}`),
		raw("flag-2", `{"type": "flag", "flag": {"key": "a.static", "variations": ["x", "y"], "apps": ["kibana", "other"],
		  "environments": {"production": {"default": "y"}, "qa": {"default": "x"}}}}`),
		raw("flag-3", `{"type": "flag", "flag": {"key": "other.only", "variations": [1, 2], "apps": ["other"],
		  "environments": {"production": {"default": 1}}}}`),
		raw("flag-4", `{"type": "flag", "flag": {"key": "qa.only", "variations": [1, 2], "apps": ["kibana"],
		  "environments": {"qa": {"default": 2}}}}`),
		raw("flag-5", `{"type": "flag", "flag": {"key": "c.broken", "variations": [true, false], "apps": ["kibana"],
		  "environments": {"production": {"default": "nope"}}}}`),
	}
	return store.NewSnapshot(append(docs, extra...)...)
}

func newTestHandler(t *testing.T, opts Options) (http.Handler, *source) {
	t.Helper()
	src := &source{}
	src.snap.Store(testSnapshot())
	return NewHandler(src, opts), src
}

type response struct {
	status int
	header http.Header
	body   map[string]any
}

func do(t *testing.T, h http.Handler, method, path, body string, headers map[string]string) response {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res := response{status: rec.Code, header: rec.Header()}
	if rec.Body.Len() > 0 {
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res.body), rec.Body.String())
	}
	return res
}

func bearer(tok string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + tok}
}

func TestNotReady(t *testing.T) {
	h := NewHandler(&source{}, Options{})
	res := do(t, h, http.MethodPost, "/ofrep/v1/evaluate/flags/a.static", `{"context": {}}`, bearer(sdkKey))
	assert.Equal(t, http.StatusServiceUnavailable, res.status)
	assert.NotEmpty(t, res.header.Get("Retry-After"))
}

func TestAuthentication(t *testing.T) {
	h, _ := newTestHandler(t, Options{})
	path := "/ofrep/v1/evaluate/flags/a.static"

	testcases := map[string]struct {
		headers map[string]string
		status  int
	}{
		"missing":             {nil, http.StatusUnauthorized},
		"unknown key":         {bearer("nope"), http.StatusUnauthorized},
		"hash is not the key": {bearer(hashKey(sdkKey)), http.StatusUnauthorized},
		"wrong scheme":        {map[string]string{"Authorization": "ApiKey " + sdkKey}, http.StatusUnauthorized},
		"sdk key":             {bearer(sdkKey), http.StatusOK},
		"client id":           {bearer(clientID), http.StatusOK},
		"x-api-key":           {map[string]string{"X-API-Key": sdkKey}, http.StatusOK},
	}
	for name, tc := range testcases {
		t.Run(name, func(t *testing.T) {
			res := do(t, h, http.MethodPost, path, `{"context": {}}`, tc.headers)
			assert.Equal(t, tc.status, res.status)
			if tc.status == http.StatusUnauthorized {
				assert.Equal(t, "Bearer", res.header.Get("WWW-Authenticate"))
			}
		})
	}
}

func TestEvaluateSingle(t *testing.T) {
	h, _ := newTestHandler(t, Options{})

	testcases := map[string]struct {
		key     string
		token   string
		context string
		status  int
		body    map[string]any
	}{
		"static": {
			key: "a.static", token: sdkKey, context: `{"context": {}}`, status: http.StatusOK,
			body: map[string]any{"key": "a.static", "value": "y", "variant": "y", "reason": "STATIC"},
		},
		"environment of the credential": {
			key: "a.static", token: "qa-key", context: `{"context": {}}`, status: http.StatusOK,
			body: map[string]any{"key": "a.static", "value": "x", "variant": "x", "reason": "STATIC"},
		},
		"targeting match with nested context": {
			key: "b.targeted", token: sdkKey, context: `{"context": {"targetingKey": "u1", "kibana": {"offering": "serverless"}}}`, status: http.StatusOK,
			body: map[string]any{"key": "b.targeted", "value": true, "variant": "true", "reason": "TARGETING_MATCH"},
		},
		"split": {
			key: "b.targeted", token: sdkKey, context: `{"context": {"targetingKey": "u1"}}`, status: http.StatusOK,
			body: map[string]any{"key": "b.targeted", "value": false, "variant": "false", "reason": "SPLIT"},
		},
		"targeting key missing": {
			key: "b.targeted", token: sdkKey, context: `{"context": {}}`, status: http.StatusBadRequest,
			body: map[string]any{"key": "b.targeted", "errorCode": "TARGETING_KEY_MISSING"},
		},
		"unknown flag": {
			key: "nope", token: sdkKey, context: `{"context": {}}`, status: http.StatusNotFound,
			body: map[string]any{"key": "nope", "errorCode": "FLAG_NOT_FOUND"},
		},
		"flag of another app": {
			key: "other.only", token: sdkKey, context: `{"context": {}}`, status: http.StatusNotFound,
			body: map[string]any{"key": "other.only", "errorCode": "FLAG_NOT_FOUND"},
		},
		"flag without the environment": {
			key: "qa.only", token: sdkKey, context: `{"context": {}}`, status: http.StatusNotFound,
			body: map[string]any{"key": "qa.only", "errorCode": "FLAG_NOT_FOUND"},
		},
		"invalid flag": {
			key: "c.broken", token: sdkKey, context: `{"context": {}}`, status: http.StatusBadRequest,
			body: map[string]any{"key": "c.broken", "errorCode": "PARSE_ERROR"},
		},
		"invalid context": {
			key: "a.static", token: sdkKey, context: `{"context": {"targetingKey": 1}}`, status: http.StatusBadRequest,
			body: map[string]any{"key": "a.static", "errorCode": "INVALID_CONTEXT"},
		},
		"malformed body": {
			key: "a.static", token: sdkKey, context: `{"context": `, status: http.StatusBadRequest,
			body: map[string]any{"key": "a.static", "errorCode": "INVALID_CONTEXT"},
		},
		"empty body": {
			key: "a.static", token: sdkKey, context: ``, status: http.StatusOK,
			body: map[string]any{"key": "a.static", "value": "y", "variant": "y", "reason": "STATIC"},
		},
	}
	for name, tc := range testcases {
		t.Run(name, func(t *testing.T) {
			res := do(t, h, http.MethodPost, "/ofrep/v1/evaluate/flags/"+tc.key, tc.context, bearer(tc.token))
			require.Equal(t, tc.status, res.status, res.body)
			delete(res.body, "errorDetails")
			assert.Equal(t, tc.body, res.body)
			assert.Equal(t, "application/json", res.header.Get("Content-Type"))
		})
	}
}

func flagKeys(t *testing.T, body map[string]any) []string {
	t.Helper()
	flags, ok := body["flags"].([]any)
	require.True(t, ok, body)
	keys := make([]string, 0, len(flags))
	for _, f := range flags {
		keys = append(keys, f.(map[string]any)["key"].(string))
	}
	return keys
}

func TestEvaluateBulk(t *testing.T) {
	h, src := newTestHandler(t, Options{})
	body := `{"context": {"targetingKey": "u1"}}`

	res := do(t, h, http.MethodPost, PathBulk, body, bearer(sdkKey))
	require.Equal(t, http.StatusOK, res.status)
	assert.Equal(t, []string{"a.static", "b.targeted", "c.broken"}, flagKeys(t, res.body), "only flags of the app and environment, sorted")
	flags := res.body["flags"].([]any)
	assert.Equal(t, "PARSE_ERROR", flags[2].(map[string]any)["errorCode"])
	tag := res.header.Get("ETag")
	require.NotEmpty(t, tag)

	other := do(t, h, http.MethodPost, PathBulk, body, bearer("other-key"))
	assert.Equal(t, []string{"a.static", "other.only"}, flagKeys(t, other.body))
	assert.NotEqual(t, tag, other.header.Get("ETag"), "the ETag depends on the caller")

	notModified := do(t, h, http.MethodPost, PathBulk, body, map[string]string{"Authorization": "Bearer " + sdkKey, "If-None-Match": tag})
	assert.Equal(t, http.StatusNotModified, notModified.status)
	assert.Nil(t, notModified.body)
	assert.Equal(t, tag, notModified.header.Get("ETag"))

	weak := do(t, h, http.MethodPost, PathBulk, body, map[string]string{"Authorization": "Bearer " + sdkKey, "If-None-Match": `"other", W/` + tag})
	assert.Equal(t, http.StatusNotModified, weak.status)

	changedCtx := do(t, h, http.MethodPost, PathBulk, `{"context": {"targetingKey": "u2"}}`, map[string]string{"Authorization": "Bearer " + sdkKey, "If-None-Match": tag})
	assert.Equal(t, http.StatusOK, changedCtx.status, "the ETag depends on the context")

	src.snap.Store(testSnapshot(raw("flag-6", `{"type": "flag", "flag": {"key": "d.new", "variations": [true, false], "apps": ["kibana"],
	  "environments": {"production": {"default": true}}}}`)))
	changed := do(t, h, http.MethodPost, PathBulk, body, map[string]string{"Authorization": "Bearer " + sdkKey, "If-None-Match": tag})
	require.Equal(t, http.StatusOK, changed.status, "the ETag depends on the definitions")
	assert.Contains(t, flagKeys(t, changed.body), "d.new")

	invalid := do(t, h, http.MethodPost, PathBulk, `{"context": {"a": {"b": 1}, "a.b": 2}}`, bearer(sdkKey))
	assert.Equal(t, http.StatusBadRequest, invalid.status)
	assert.Equal(t, "INVALID_CONTEXT", invalid.body["errorCode"])
}

func TestCORS(t *testing.T) {
	h, _ := newTestHandler(t, Options{AllowedOrigins: []string{"https://app.example.com/"}})

	preflight := do(t, h, http.MethodOptions, PathBulk, "", map[string]string{
		"Origin":                        "https://app.example.com",
		"Access-Control-Request-Method": "POST",
	})
	assert.Equal(t, http.StatusNoContent, preflight.status, "preflight does not need credentials")
	assert.Equal(t, "https://app.example.com", preflight.header.Get("Access-Control-Allow-Origin"))
	assert.Contains(t, preflight.header.Get("Access-Control-Allow-Headers"), "Authorization")
	assert.Contains(t, preflight.header.Get("Access-Control-Allow-Headers"), "If-None-Match")
	assert.Contains(t, preflight.header.Get("Access-Control-Allow-Methods"), "POST")

	denied := do(t, h, http.MethodOptions, PathBulk, "", map[string]string{"Origin": "https://evil.example.com"})
	assert.Empty(t, denied.header.Get("Access-Control-Allow-Origin"))

	actual := do(t, h, http.MethodPost, PathBulk, `{"context": {}}`, map[string]string{
		"Origin": "https://app.example.com", "Authorization": "Bearer " + clientID,
	})
	assert.Equal(t, http.StatusOK, actual.status)
	assert.Equal(t, "https://app.example.com", actual.header.Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "ETag", actual.header.Get("Access-Control-Expose-Headers"))

	unauthorized := do(t, h, http.MethodPost, PathBulk, `{"context": {}}`, map[string]string{"Origin": "https://app.example.com"})
	assert.Equal(t, http.StatusUnauthorized, unauthorized.status)
	assert.Equal(t, "https://app.example.com", unauthorized.header.Get("Access-Control-Allow-Origin"), "errors are readable by the browser")

	wildcard := NewHandler(&source{}, Options{AllowedOrigins: []string{"*"}})
	res := do(t, wildcard, http.MethodOptions, PathBulk, "", map[string]string{"Origin": "https://any.example.com"})
	assert.Equal(t, "https://any.example.com", res.header.Get("Access-Control-Allow-Origin"))
}

func TestObserver(t *testing.T) {
	rec := &recorder{}
	h, _ := newTestHandler(t, Options{Observer: rec})

	do(t, h, http.MethodPost, "/ofrep/v1/evaluate/flags/a.static", `{"context": {"targetingKey": "u1", "org": {"id": 12345678901234567890}}}`, bearer(sdkKey))
	do(t, h, http.MethodPost, PathBulk, `{"context": {"targetingKey": "u2"}}`, bearer(sdkKey))
	do(t, h, http.MethodPost, PathBulk, `{"context": {"targetingKey": "u3"}}`, nil)

	rec.mu.Lock()
	defer rec.mu.Unlock()
	require.Len(t, rec.seen, 2, "unauthenticated requests are not observed")
	assert.Equal(t, "u1", rec.seen[0].TargetingKey())
	assert.Equal(t, json.Number("12345678901234567890"), rec.seen[0]["org.id"], "numbers keep their precision")
	assert.Equal(t, "u2", rec.seen[1].TargetingKey())
}

func TestBodyTooLarge(t *testing.T) {
	h, _ := newTestHandler(t, Options{})
	limited := http.MaxBytesHandler(h, 16)
	res := do(t, limited, http.MethodPost, "/ofrep/v1/evaluate/flags/a.static", `{"context": {"targetingKey": "a very long key"}}`, bearer(sdkKey))
	assert.Equal(t, http.StatusRequestEntityTooLarge, res.status)
}

func TestTrailingRequestBody(t *testing.T) {
	h, _ := newTestHandler(t, Options{})
	res := do(t, h, http.MethodPost, "/ofrep/v1/evaluate/flags/a.static", `{"context":{}}   `, bearer(sdkKey))
	assert.Equal(t, http.StatusOK, res.status, "whitespace after the JSON value is consumed")

	res = do(t, h, http.MethodPost, "/ofrep/v1/evaluate/flags/a.static", `{"context":{}}{"context":{}}`, bearer(sdkKey))
	assert.Equal(t, http.StatusBadRequest, res.status)

	limited := http.MaxBytesHandler(h, 64)
	padded := `{"context":{}}` + strings.Repeat(" ", 128)
	res = do(t, limited, http.MethodPost, "/ofrep/v1/evaluate/flags/a.static", padded, bearer(sdkKey))
	assert.Equal(t, http.StatusRequestEntityTooLarge, res.status)
}
