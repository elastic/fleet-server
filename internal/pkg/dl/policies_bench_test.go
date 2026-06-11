// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dl

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

// makePolicyHit produces a synthetic es.HitT for a policy document. When
// withTarget is false the outputs map contains only a non-matching "default"
// output; when true it also contains the "remote" output being searched for.
func makePolicyHit(withTarget bool) es.HitT {
	outputs := map[string]map[string]any{
		"default": {"type": "elasticsearch", "hosts": []string{"https://es:9200"}},
	}
	if withTarget {
		outputs["remote"] = map[string]any{
			"type":  "remote_elasticsearch",
			"hosts": []string{"https://remote-es:9200"},
		}
	}
	data := &model.PolicyData{
		ID:       "policy-bench-id",
		Revision: 1,
		Outputs:  outputs,
		Inputs: []map[string]any{
			{
				"type":    "logfile",
				"streams": []map[string]any{{"paths": []string{"/var/log/*.log"}}},
			},
			{
				"type":    "metrics",
				"streams": []map[string]any{{"metricsets": []string{"cpu", "memory", "network"}}},
			},
		},
		OutputPermissions: json.RawMessage(`{"default":{"_fallback":{"indices":[{"names":["logs-*","metrics-*"],"privileges":["auto_configure","create_doc"]}]}}}`),
	}
	policy := model.Policy{
		PolicyID:    "policy-bench-id",
		RevisionIdx: 1,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Data:        data,
	}
	src, err := json.Marshal(policy)
	if err != nil {
		panic(err)
	}
	return es.HitT{Source: src}
}

// BenchmarkQueryPoliciesRender measures the cost of rendering the zero-token
// policies template. QueryOutputFromPolicy calls Render with an empty params
// map on every invocation; this benchmark captures that overhead.
func BenchmarkQueryPoliciesRender(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_, err := tmplQueryPolicies.Render(map[string]any{})
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkQueryOutputFromPolicyUnmarshal measures the unmarshal cost of the
// inner loop in QueryOutputFromPolicy. It creates 100 non-matching hits so
// that all are traversed, matching the worst-case production path.
func BenchmarkQueryOutputFromPolicyUnmarshal(b *testing.B) {
	const n = 100
	hits := make([]es.HitT, n)
	for i := range hits {
		hits[i] = makePolicyHit(false)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		var policy model.Policy
		for _, hit := range hits {
			if err := hit.Unmarshal(&policy); err != nil {
				b.Fatal(err)
			}
			if policy.Data != nil && policy.Data.Outputs["remote"] != nil {
				break
			}
		}
	}
}
