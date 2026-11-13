// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dl

import (
	"context"
	"encoding/json"
	"errors"
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

// TestQueryLatestPolicySharesStrings verifies that equal long strings of the policy share memory
// and that the policy still gets its Elasticsearch metadata.
func TestQueryLatestPolicySharesStrings(t *testing.T) {
	query := strings.Repeat("SELECT name, path FROM processes WHERE ", 4)
	bulker := searchOnlyBulk{
		res: &es.ResultT{
			HitsT: es.HitsT{
				Hits: []es.HitT{
					{
						ID:     "doc-1",
						SeqNo:  11,
						Source: policySource(fmt.Sprintf(`[{"query":%q},{"query":%q}]`, query, query)),
					},
				},
			},
		},
	}

	policy, err := QueryLatestPolicy(t.Context(), bulker, "p")
	require.NoError(t, err)

	queryOf := func(i int) string {
		q, ok := policy.Data.Inputs[i]["query"].(string)
		require.True(t, ok)
		return q
	}
	assert.Equal(t, query, queryOf(0))
	assert.Equal(t, query, queryOf(1))
	assert.True(t, sameBacking(queryOf(0), queryOf(1)), "the inputs share the query")
	assert.Equal(t, "doc-1", policy.Id, "Elasticsearch metadata is set as hit.Unmarshal does")
	assert.Equal(t, int64(11), policy.SeqNo)
}

// recordingBulk records the query it is asked to run and answers Search with a canned result.
type recordingBulk struct {
	bulk.Bulk
	res   *es.ResultT
	query []byte
	err   error
}

func (b *recordingBulk) Search(_ context.Context, _ string, query []byte, _ ...bulk.Opt) (*es.ResultT, error) {
	b.query = query
	return b.res, b.err
}

func TestQueryLatestPolicyQuery(t *testing.T) {
	t.Run("query", func(t *testing.T) {
		bulker := &recordingBulk{res: &es.ResultT{}}
		_, err := QueryLatestPolicy(t.Context(), bulker, "policy-1")
		require.ErrorIs(t, err, ErrNotFound)
		assert.JSONEq(t, `{
			"size": 1,
			"query": {"bool": {"filter": [{"term": {"policy_id": "policy-1"}}]}},
			"sort": [{"revision_idx": "desc"}]
		}`, string(bulker.query))
	})

	t.Run("policy id is a value, not part of the query syntax", func(t *testing.T) {
		const id = `a"}]}} , "x": "y`
		bulker := &recordingBulk{res: &es.ResultT{}}
		_, err := QueryLatestPolicy(t.Context(), bulker, id)
		require.ErrorIs(t, err, ErrNotFound)

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

	t.Run("search error", func(t *testing.T) {
		errSearch := errors.New("search failed")
		_, err := QueryLatestPolicy(t.Context(), &recordingBulk{err: errSearch}, "policy-1")
		require.ErrorIs(t, err, errSearch)
	})
}

// searchesBulk answers each Search with the next of res and records the queries.
type searchesBulk struct {
	bulk.Bulk
	res     []*es.ResultT
	queries []string
}

func (b *searchesBulk) Search(_ context.Context, _ string, query []byte, _ ...bulk.Opt) (*es.ResultT, error) {
	b.queries = append(b.queries, string(query))
	if len(b.queries) > len(b.res) {
		return nil, errors.New("unexpected search")
	}
	return b.res[len(b.queries)-1], nil
}

func TestQueryLatestPolicyDefaultFleetServer(t *testing.T) {
	policyIDs := &es.ResultT{
		Aggregations: map[string]es.Aggregation{
			FieldPolicyID: {
				Buckets: []es.Bucket{
					{Key: "old-default"},
					{Key: "default"},
				},
			},
		},
	}

	t.Run("policy whose latest revision is the default", func(t *testing.T) {
		bulker := &searchesBulk{
			res: []*es.ResultT{
				policyIDs,
				{
					HitsT: es.HitsT{
						Hits: []es.HitT{
							{Source: []byte(`{"policy_id":"old-default","revision_idx":5,"default_fleet_server":false}`)},
							{Source: []byte(`{"policy_id":"default","revision_idx":2,"default_fleet_server":true}`)},
						},
					},
				},
			},
		}

		policy, err := QueryLatestPolicy(t.Context(), bulker, "", WithDefaultFleetServerFallback())
		require.NoError(t, err)

		assert.Equal(t, "default", policy.PolicyID)
		assert.Equal(t, int64(2), policy.RevisionIdx)
		require.Len(t, bulker.queries, 2)
		assert.JSONEq(t, `{
			"size": 0,
			"query": {"bool": {"filter": [{"term": {"default_fleet_server": true}}]}},
			"aggs": {"policy_id": {"terms": {"field": "policy_id", "size": 10000}}}
		}`, bulker.queries[0], "the IDs of the policies with a default revision")
		assert.JSONEq(t, `{
			"size": 2,
			"query": {"bool": {"filter": [{"terms": {"policy_id": ["old-default", "default"]}}]}},
			"collapse": {"field": "policy_id"},
			"sort": [{"revision_idx": "desc"}]
		}`, bulker.queries[1], "the latest revision of each of these policies")
	})

	t.Run("no policy with a default revision", func(t *testing.T) {
		bulker := &searchesBulk{
			res: []*es.ResultT{
				{},
			},
		}
		_, err := QueryLatestPolicy(t.Context(), bulker, "", WithDefaultFleetServerFallback())
		require.ErrorIs(t, err, ErrNotFound)
		assert.Len(t, bulker.queries, 1)
	})

	t.Run("empty policy ID without the fallback", func(t *testing.T) {
		bulker := &searchesBulk{}
		_, err := QueryLatestPolicy(t.Context(), bulker, "")
		require.ErrorIs(t, err, ErrNotFound)
		assert.Empty(t, bulker.queries, "nothing is searched for")
	})
}
