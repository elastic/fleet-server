// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dsl

import (
	"encoding/json"
	"fmt"
	"testing"
)

// Emulate agent_id saved object query
func makeQuery(leaf interface{}) *Node {
	const ty = "fleet-agents"

	root := NewRoot()
	mustNode := root.Query().Bool().Must()
	mustNode.Term("type", ty, nil)
	mustNode.Term("fleet-agents.access_api_key_id", leaf, nil)
	return root
}

func makeQuery2(leaf1 interface{}, leaf2 interface{}) *Node {
	const ty = "fleet-agent-actions"

	root := NewRoot()
	root.Size(1)
	root.Sort().SortOrder("fleet-agent-actions.created_at", SortDescend)

	mustNode := root.Query().Bool().Must()
	mustNode.Term("type", ty, nil)
	mustNode.Term("fleet-agent-actions.policy_id", leaf1, nil)
	mustNode.Range("fleet-agent-actions.policy_revision", WithRangeGT(leaf2))
	return root
}

func BenchmarkRenderOne(b *testing.B) {
	const kName = "api_key"
	tmpl := NewTmpl()
	token := tmpl.Bind(kName)

	query := makeQuery(token)

	if err := tmpl.Resolve(query); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	// run the RenderOne function b.N times
	for n := 0; n < b.N; n++ {
		if _, err := tmpl.RenderOne(kName, "2Ye0F3UByTc0c1e9OeMO"); err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkRender(b *testing.B) {
	const kName = "api_key"
	tmpl := NewTmpl()
	token := tmpl.Bind(kName)

	query := makeQuery(token)

	if err := tmpl.Resolve(query); err != nil {
		b.Fatal(err)
	}

	const v = "2Ye0F3UByTc0c1e9OeMO"

	b.ResetTimer()
	// run the RenderOne function b.N times
	for n := 0; n < b.N; n++ {
		if _, err := tmpl.Render(map[string]interface{}{
			kName: v,
		}); err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkMarshalNode(b *testing.B) {
	// run the RenderOne function b.N times
	query := makeQuery("2Ye0F3UByTc0c1e9OeMO")
	var err error
	var p []byte
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		p, err = json.Marshal(query)
	}
	if len(p) == 0 || err != nil {
		b.Errorf("sanity check failed, p=%v err: %v", p, err)
	}
}

func BenchmarkMarshalNode2(b *testing.B) {
	// run the RenderOne function b.N times
	query := makeQuery2("27e58fc0-09a2-11eb-a8cd-57e98f140de5", 3)
	var err error
	var p []byte
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		p, err = json.Marshal(query)
	}
	if len(p) == 0 || err != nil {
		b.Errorf("sanity check failed, p=%v err: %v", p, err)
	}
}

func BenchmarkSprintf(b *testing.B) {
	queryTmpl := `{"size": 1,"sort": [{"fleet-agent-actions.created_at": {"order": "DESC"}}],"query": {"bool": {"must": [{"term": {"type": "fleet-agent-actions"}},{"term": {"fleet-agent-actions.policy_id": "%s"}},{"range": {"fleet-agent-actions.policy_revision": {"gt": %d}}}]}}}`

	policyID := "27e58fc0-09a2-11eb-a8cd-57e98f140de5"
	policyRev := 3

	var s string
	var ssprintres string
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		s = fmt.Sprintf(queryTmpl, policyID, policyRev)
	}
	ssprintres = s
	if len(ssprintres) == 0 {
		b.Error("Sprintf had len 0")
	}
}

func BenchmarkRender2(b *testing.B) {
	const kName1 = "policyId"
	const kName2 = "policyRev"

	tmpl := NewTmpl()
	token1 := tmpl.Bind(kName1)
	token2 := tmpl.Bind(kName2)

	query := makeQuery2(token1, token2)

	if err := tmpl.Resolve(query); err != nil {
		b.Fatal(err)
	}

	// run the RenderOne function b.N times
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if _, err := tmpl.Render(map[string]interface{}{
			kName1: "27e58fc0-09a2-11eb-a8cd-57e98f140de5",
			kName2: 3,
		}); err != nil {
			b.Error(err)
		}
	}
}
