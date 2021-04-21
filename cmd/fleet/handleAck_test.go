// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"testing"

	"encoding/json"
)

func BenchmarkMakeUpdatePolicyBody(b *testing.B) {
	b.ReportAllocs()

	const policyId = "ed110be4-c2a0-42b8-adc0-94c2f0569207"
	const newRev = 2
	const coord = 1

	for n := 0; n < b.N; n++ {
		makeUpdatePolicyBody(policyId, newRev, coord)
	}
}

func TestMakeUpdatePolicyBody(t *testing.T) {

	const policyId = "ed110be4-c2a0-42b8-adc0-94c2f0569207"
	const newRev = 2
	const coord = 1

	data := makeUpdatePolicyBody(policyId, newRev, coord)

	var i interface{}
	err := json.Unmarshal(data, &i)

	if err != nil {
		t.Fatal(err)
	}
}
