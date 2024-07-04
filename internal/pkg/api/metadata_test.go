// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration

package api

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_ParseDownloadRate(t *testing.T) {
	tests := []struct {
		name           string
		raw            json.RawMessage
		expectedErrMsg string
		expectedValue  float64
	}{{
		name:          "download rate as float",
		raw:           json.RawMessage(`1000000`),
		expectedValue: 1000000.00,
	}, {
		name:          "download rate as MBps",
		raw:           json.RawMessage(`"1MBps"`),
		expectedValue: 1000000.00,
	}, {
		name:           "download rate random string",
		raw:            json.RawMessage(`"toto"`),
		expectedErrMsg: "error converting download_rate from human size: invalid size: 'toto'",
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			res, err := parseDownloadRate(tc.raw)
			if tc.expectedErrMsg != "" {
				fmt.Printf("TEST %v+", err)
				require.ErrorContains(t, err, tc.expectedErrMsg)
			} else {
				require.NoError(t, err)
				require.NotNil(t, res)
				require.Equal(t, tc.expectedValue, *res)
			}

		})
	}
}
