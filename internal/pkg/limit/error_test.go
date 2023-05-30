// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package limit

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{{
		name: "unknown",
		err:  errors.New("unknown"),
		want: "UnknownLimiterError",
	}, {
		name: "rate limit",
		err:  ErrRateLimit,
		want: "RateLimit",
	}, {
		name: "max limit",
		err:  ErrMaxLimit,
		want: "MaxLimit",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			err := writeError(w, tt.err)
			require.NoError(t, err)
			resp := w.Result()
			defer resp.Body.Close()
			require.Equal(t, http.StatusTooManyRequests, resp.StatusCode)

			var body struct {
				Status int    `json:"statusCode"`
				Error  string `json:"error"`
			}
			dec := json.NewDecoder(resp.Body)
			err = dec.Decode(&body)
			require.NoError(t, err)
			require.Equal(t, http.StatusTooManyRequests, body.Status)
			require.Equal(t, tt.want, body.Error)
		})
	}
}
