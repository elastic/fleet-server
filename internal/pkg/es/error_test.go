// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration
// +build !integration

package es

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestErrorTranslation(t *testing.T) {
	testCases := []struct {
		Status          int
		Name            string
		Payload         []byte
		IsErrorExpected bool
		ExpectedType    string
		ExpectedReason  string
	}{
		{200, "ok error", []byte("this is ignored"), false, "", ""},
		{
			500,
			"nil error",
			nil,
			true,
			"",
			"",
		},
		{
			500,
			"empty error",
			[]byte{},
			true,
			"",
			"",
		},
		{
			500,
			"unknown error",
			[]byte("this will be unknown"),
			true,
			unknownErrorType,
			"this will be unknown",
		},
		{
			500,
			"version conflict error",
			[]byte("this will have elastic version conflict included"),
			true,
			versionConflictErrorType,
			"this will have elastic version conflict included",
		},
		{
			500,
			"elastic not found error",
			[]byte("this will have elastic not found included"),
			true,
			unknownErrorType,
			"this will have elastic not found included",
		},
		{
			500,
			"invalid body error",
			[]byte("this will have invalid body included"),
			true,
			unknownErrorType,
			"this will have invalid body included",
		},
		{
			500,
			"index not found error",
			[]byte("this will have index not found included"),
			true,
			indexNotFoundErrorType,
			"this will have index not found included",
		},
		{
			500,
			"timeout error",
			[]byte("this will have timeout included"),
			true,
			timeoutErrorType,
			"this will have timeout included",
		},
		{
			500,
			"not found error",
			[]byte("this will have generic not found included"),
			true,
			unknownErrorType,
			"this will have generic not found included",
		},
		{
			500,
			"timeout_exception error",
			[]byte("this will have timeout_exception included"),
			true,
			timeoutErrorType,
			"this will have timeout_exception included",
		},
		{
			500,
			"index_not_found_exception error",
			[]byte("this will have index_not_found_exception included"),
			true,
			indexNotFoundErrorType,
			"this will have index_not_found_exception included",
		},
		{
			500,
			"version_conflict_engine_exception error",
			[]byte("this will have version_conflict_engine_exception included"),
			true,
			versionConflictErrorType,
			"this will have version_conflict_engine_exception included",
		},
		{
			500,
			"detailed versioned conflict error",
			errorTinBytes(ErrorT{
				Type:   "version_conflict_engine_exception",
				Reason: "some reason",
			}),
			true,
			"version_conflict_engine_exception",
			"some reason",
		},
		{
			500,
			"detailed index not found error",
			errorTinBytes(ErrorT{
				Type:   "index_not_found_exception",
				Reason: "some reason",
			}),
			true,
			"index_not_found_exception",
			"some reason",
		},
		{
			500,
			"detailed timeout conflict error",
			errorTinBytes(ErrorT{
				Type:   "timeout_exception",
				Reason: "some reason",
			}),
			true,
			"timeout_exception",
			"some reason",
		},
		{
			404,
			"detailed index not found json",
			[]byte(`{
				"root_cause": [
				  {
					"type": "index_not_found_exception",
					"reason": "no such index [.fleet-actions]",
					"resource.type": "index_expression",
					"resource.id": ".fleet-actions",
					"index_uuid": "_na_",
					"index": ".fleet-actions"
				  }
				],
				"type": "index_not_found_exception",
				"reason": "no such index [.fleet-actions]",
				"resource.type": "index_expression",
				"resource.id": ".fleet-actions",
				"index_uuid": "_na_",
				"index": ".fleet-actions"
			  }`),
			true,
			indexNotFoundErrorType,
			`no such index [.fleet-actions]`,
		},
		{
			404,
			"index not found json",
			[]byte("IndexNotFoundException[no such index [.fleet-actions]]"),
			true,
			indexNotFoundErrorType,
			"IndexNotFoundException[no such index [.fleet-actions]]",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			err := TranslateError(tc.Status, tc.Payload)
			if !tc.IsErrorExpected {
				require.True(t, err == nil, "error not expected but returned")
				return
			}

			require.True(t, err != nil, "error is expected but not returned")

			if tc.ExpectedType == versionConflictErrorType {
				require.Equal(t, ErrElasticVersionConflict, err)
				return
			}
			elasticErr, ok := err.(*ErrElastic)
			require.True(t, ok, "elastic error is required")
			require.Equal(t, tc.ExpectedType, elasticErr.Type)
			require.Equal(t, tc.ExpectedReason, elasticErr.Reason)
		})
	}
}

func errorTinBytes(e ErrorT) []byte {
	b, _ := json.Marshal(e)
	return b
}
