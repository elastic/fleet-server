// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dl

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
)

// searchOnlyBulk answers Search with a canned result; any other method panics (nil embedded interface).
type searchOnlyBulk struct {
	bulk.Bulk
	res *es.ResultT
}

func (b searchOnlyBulk) Search(context.Context, string, []byte, ...bulk.Opt) (*es.ResultT, error) {
	return b.res, nil
}

// policySource returns a policy document whose inputs are the given JSON array.
func policySource(inputs string) []byte {
	return fmt.Appendf(nil, `{"policy_id":"p","revision_idx":3,"@timestamp":"2026-01-01T00:00:00Z","namespaces":["a"],`+
		`"data":{"id":"p","revision":3,"outputs":{"o":{"type":"elasticsearch","hosts":["h"]}},"agent":{"x":{"y":1}},"inputs":%s}}`, inputs)
}

// TestQueryLatestPoliciesSharesStrings verifies that the policies QueryLatestPolicies returns share
// the memory of equal long strings, and that they still get their Elasticsearch metadata.
func TestQueryLatestPoliciesSharesStrings(t *testing.T) {
	query := strings.Repeat("SELECT name, path FROM processes WHERE ", 4)
	buckets := make([]es.Bucket, 2)
	for i := range buckets {
		hit := es.HitT{
			ID:     fmt.Sprintf("doc-%d", i),
			SeqNo:  int64(10 + i),
			Source: policySource(fmt.Sprintf(`[{"query":%q}]`, query)),
		}
		buckets[i] = es.Bucket{
			Key:          fmt.Sprintf("policy-%d", i),
			Aggregations: map[string]es.HitsT{FieldRevisionIdx: {Hits: []es.HitT{hit}}},
		}
	}
	bulker := searchOnlyBulk{res: &es.ResultT{
		Aggregations: map[string]es.Aggregation{FieldPolicyID: {Buckets: buckets}},
	}}

	policies, err := QueryLatestPolicies(context.Background(), bulker)
	require.NoError(t, err)
	require.Len(t, policies, 2)

	queryOf := func(i int) string {
		q, ok := policies[i].Data.Inputs[0]["query"].(string)
		require.True(t, ok)
		return q
	}
	assert.Equal(t, query, queryOf(0))
	assert.Equal(t, query, queryOf(1))
	assert.True(t, sameBacking(queryOf(0), queryOf(1)), "the policies share the query")
	assert.Equal(t, "doc-1", policies[1].Id, "Elasticsearch metadata is set as hit.Unmarshal does")
	assert.Equal(t, int64(11), policies[1].SeqNo)
}

// recordingBulk records the query it is asked to run and answers Search with a canned result.
type recordingBulk struct {
	bulk.Bulk
	res   *es.ResultT
	query []byte
}

func (b *recordingBulk) Search(_ context.Context, _ string, query []byte, _ ...bulk.Opt) (*es.ResultT, error) {
	b.query = query
	return b.res, nil
}

func TestQueryLatestPoliciesQuery(t *testing.T) {
	t.Run("all policies", func(t *testing.T) {
		bulker := &recordingBulk{res: &es.ResultT{}}
		_, err := QueryLatestPolicies(context.Background(), bulker)
		require.NoError(t, err)
		assert.JSONEq(t, `{
			"size": 0,
			"aggs": {"policy_id": {
				"terms": {"field": "policy_id", "size": 10000},
				"aggs": {"revision_idx": {"top_hits": {"size": 1, "sort": [{"revision_idx": "desc"}]}}}
			}}
		}`, string(bulker.query))
	})

	t.Run("one policy", func(t *testing.T) {
		bulker := &recordingBulk{res: &es.ResultT{}}
		_, err := QueryLatestPolicies(context.Background(), bulker, WithPolicyID("policy-1"))
		require.NoError(t, err)

		var got, all map[string]any
		require.NoError(t, json.Unmarshal(bulker.query, &got))
		require.NoError(t, json.Unmarshal(tmplQueryLatestPolicies, &all))

		query, err := json.Marshal(got["query"])
		require.NoError(t, err)
		assert.JSONEq(t, `{"bool": {"filter": [{"term": {"policy_id": "policy-1"}}]}}`, string(query))

		// Apart from the filter, it is the query for all policies, so both take the same code path.
		delete(got, "query")
		assert.Equal(t, all, got)
	})

	t.Run("policy id is a value, not part of the query syntax", func(t *testing.T) {
		const id = `a"}]}} , "x": "y`
		bulker := &recordingBulk{res: &es.ResultT{}}
		_, err := QueryLatestPolicies(context.Background(), bulker, WithPolicyID(id))
		require.NoError(t, err)

		var got struct {
			Query struct {
				Bool struct {
					Filter []struct {
						Term struct {
							PolicyID string `json:"policy_id"`
						} `json:"term"`
					} `json:"filter"`
				} `json:"bool"`
			} `json:"query"`
		}
		require.NoError(t, json.Unmarshal(bulker.query, &got))
		require.Len(t, got.Query.Bool.Filter, 1)
		assert.Equal(t, id, got.Query.Bool.Filter[0].Term.PolicyID)
	})
}
