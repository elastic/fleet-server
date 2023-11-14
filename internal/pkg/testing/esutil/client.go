// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package esutil

import (
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/stretchr/testify/require"
)

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

func MockESClient(t *testing.T) (*elasticsearch.Client, *MockTransport) {
	mocktrans := MockTransport{
		Response: sendBodyString("{}"), //nolint:bodyclose // nopcloser is used, linter does not see it
	}

	mocktrans.RoundTripFn = func(req *http.Request) (*http.Response, error) { return mocktrans.Response, nil }
	client, err := elasticsearch.NewClient(elasticsearch.Config{
		Transport: &mocktrans,
	})
	require.NoError(t, err)
	return client, &mocktrans
}

func sendBodyString(body string) *http.Response {
	return sendBody(strings.NewReader(body))
}
func sendBody(body io.Reader) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       ioutil.NopCloser(body),
		Header: http.Header{
			"X-Elastic-Product": []string{"Elasticsearch"},
			"Content-Type":      []string{"application/cbor"},
		},
	}
}
