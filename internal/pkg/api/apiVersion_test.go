// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"encoding/json"
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
		requestAPIVersionHeader    string
		expectRespStatus           string
		expectRespAPIVersionHeader string
		expectErr                  string
	}{
		{
			name:                    "with a misformatted Elastic-Api-Version header",
			requestAPIVersionHeader: "iamnotvalid",
			expectRespStatus:        "400 Bad Request",
			expectErr:               "ErrInvalidAPIVersionFormat",
		},
		{
			name:                    "with an invalid Elastic-Api-Version header",
			requestAPIVersionHeader: "1990-01-01",
			expectRespStatus:        "400 Bad Request",
			expectErr:               "ErrUnsupportedAPIVersion",
		},
		{
			name:                       "with a valid Elastic-Api-Version header",
			requestAPIVersionHeader:    "2022-02-01",
			expectRespAPIVersionHeader: "2022-02-01",
			expectRespStatus:           "200 OK",
		},
		{
			name:                       "without Elastic-Api-Version header",
			expectRespAPIVersionHeader: "2022-03-01",
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

			if tc.requestAPIVersionHeader != "" {
				req.Header.Set(ElasticAPIVersionHeader, tc.requestAPIVersionHeader)
			}

			apiVersion.middleware(nextHandler).ServeHTTP(resp, req)

			respResult := resp.Result()
			defer respResult.Body.Close()

			if tc.expectRespStatus != "" {
				assert.Equal(t, tc.expectRespStatus, respResult.Status)
			}

			if tc.expectRespAPIVersionHeader != "" {
				assert.Equal(t, tc.expectRespAPIVersionHeader, resp.Header().Get(ElasticAPIVersionHeader))
			}

			if tc.expectErr != "" {
				errorResp := &Error{}
				dec := json.NewDecoder(resp.Body)
				err := dec.Decode(&errorResp)

				assert.NoError(t, err)
				assert.Equal(t, tc.expectErr, errorResp.Error)
			}
		})
	}
}
