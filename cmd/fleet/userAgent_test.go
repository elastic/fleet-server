// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/go-version"
)

func TestValidateUserAgent(t *testing.T) {
	tests := []struct {
		userAgent string
		verCon    version.Constraints
		err       error
	}{
		{
			userAgent: "",
			verCon:    nil,
			err:       ErrInvalidUserAgent,
		},
		{
			userAgent: "bad value",
			verCon:    nil,
			err:       ErrInvalidUserAgent,
		},
		{
			userAgent: "eLaStIc AGeNt",
			verCon:    nil,
			err:       ErrInvalidUserAgent,
		},
		{
			userAgent: "eLaStIc AGeNt v7.10.0",
			verCon:    mustBuildConstraints("7.13.0"),
			err:       ErrUnsupportedVersion,
		},
		{
			userAgent: "eLaStIc AGeNt v7.11.1",
			verCon:    mustBuildConstraints("7.13.0"),
			err:       ErrUnsupportedVersion,
		},
		{
			userAgent: "eLaStIc AGeNt v7.12.5",
			verCon:    mustBuildConstraints("7.13.0"),
			err:       ErrUnsupportedVersion,
		},
		{
			userAgent: "eLaStIc AGeNt v7.13.0",
			verCon:    mustBuildConstraints("7.13.0"),
			err:       nil,
		},
		{
			userAgent: "eLaStIc AGeNt v7.13.0",
			verCon:    mustBuildConstraints("7.13.1"),
			err:       nil,
		},
		{
			userAgent: "eLaStIc AGeNt v7.13.1",
			verCon:    mustBuildConstraints("7.13.0"),
			err:       nil,
		},
		{
			userAgent: "eLaStIc AGeNt v7.14.0",
			verCon:    mustBuildConstraints("7.13.0"),
			err:       ErrUnsupportedVersion,
		},
		{
			userAgent: "eLaStIc AGeNt v8.0.0",
			verCon:    mustBuildConstraints("7.13.0"),
			err:       ErrUnsupportedVersion,
		},
		{
			userAgent: "eLaStIc AGeNt v7.13.0",
			verCon:    mustBuildConstraints("8.0.0"),
			err:       nil,
		},
	}
	for _, tr := range tests {
		t.Run(tr.userAgent, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("User-Agent", tr.userAgent)
			res := validateUserAgent(req, tr.verCon)
			if tr.err != res {
				t.Fatalf("err mismatch: %v != %v", tr.err, res)
			}
		})
	}
}

func mustBuildConstraints(verStr string) version.Constraints {
	con, err := buildVersionConstraint(verStr)
	if err != nil {
		panic(err)
	}
	return con
}
