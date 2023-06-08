// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAPIVersion_middleware(t *testing.T) {
	supportedVersions := []string{"2022-01-01", "2022-02-01", "2022-03-01"}
	defaultVersion := "2022-03-01"

	tests := []struct {
		name                       string
		requestApiVersionHeader    string
		expectRespStatus           string
		expectRespApiVersionHeader string
	}{
		{
			name:                    "with a misformatted elastic-api-version header",
			requestApiVersionHeader: "iamnotvalid",
			expectRespStatus:        "400 Bad Request",
		},
		{
			name:                    "with an invalid elastic-api-version header",
			requestApiVersionHeader: "1990-01-01",
			expectRespStatus:        "400 Bad Request",
		},
		{
			name:                       "with a valid elastic-api-version header",
			requestApiVersionHeader:    "2022-02-01",
			expectRespApiVersionHeader: "2022-02-01",
			expectRespStatus:           "200 OK",
		},
		{
			name:                       "without elastic-api-version header",
			expectRespApiVersionHeader: "2022-03-01",
			expectRespStatus:           "200 OK",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			apiVersion := apiVersion{
				supportedVersions: supportedVersions,
				defaultVersion:    defaultVersion,
			}

			resp := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/api/test", nil)

			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

			if tc.requestApiVersionHeader != "" {
				req.Header.Set(ElasticAPIVersionHeader, tc.requestApiVersionHeader)
			}

			apiVersion.middleware(nextHandler).ServeHTTP(resp, req)

			if tc.expectRespStatus != "" {
				assert.Equal(t, tc.expectRespStatus, resp.Result().Status)
			}

			if tc.expectRespApiVersionHeader != "" {
				assert.Equal(t, tc.expectRespApiVersionHeader, resp.Header().Get(ElasticAPIVersionHeader))
			}
		})
	}
}
