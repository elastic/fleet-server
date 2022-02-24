// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"testing"

	"encoding/json"

	"github.com/stretchr/testify/assert"
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

func TestEventToActionResult(t *testing.T) {
	agentId := "6e9b6655-8cfe-4eb6-9b2f-c10aefae7517"

	tests := []struct {
		name string
		ev   Event
	}{
		{
			name: "success",
			ev: Event{
				ActionId:        "1b12dcd8-bde0-4045-92dc-c4b27668d733",
				ActionInputType: "osquery",
				StartedAt:       "2022-02-23T18:26:08.506128Z",
				CompletedAt:     "2022-02-23T18:26:08.507593Z",
				ActionData:      []byte(`{"query": "select * from osquery_info"}`),
				ActionResponse:  []byte(`{"osquery": {"count": 1}}`),
			},
		},
		{
			name: "error",
			ev: Event{
				ActionId:        "2b12dcd8-bde0-4045-92dc-c4b27668d733",
				ActionInputType: "osquery",
				StartedAt:       "2022-02-24T18:26:08.506128Z",
				CompletedAt:     "2022-02-24T18:26:08.507593Z",
				ActionData:      []byte(`{"query": "select * from osquery_info"}`),
				Error:           "action undefined",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			acr := eventToActionResult(agentId, tc.ev)
			assert.Equal(t, agentId, acr.AgentId)
			assert.Equal(t, tc.ev.ActionId, acr.ActionId)
			assert.Equal(t, tc.ev.ActionInputType, acr.ActionInputType)
			assert.Equal(t, tc.ev.StartedAt, acr.StartedAt)
			assert.Equal(t, tc.ev.CompletedAt, acr.CompletedAt)
			assert.Equal(t, tc.ev.ActionData, acr.ActionData)
			assert.Equal(t, tc.ev.ActionResponse, acr.ActionResponse)
			assert.Equal(t, tc.ev.Error, acr.Error)
		})
	}
}
