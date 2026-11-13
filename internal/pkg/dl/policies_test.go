// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
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

// recordingBulk records the query it is asked to run and answers Search and MSearch with canned
// results.
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
}

// policyMSearchBulk answers MSearch with the item of each searched policy.
type policyMSearchBulk struct {
	bulk.Bulk
	items map[string]bulk.MsearchResponseItem
}

// errRequestFailed is the error of a failed _msearch request.
var errRequestFailed = errors.New("request failed")

func (b *policyMSearchBulk) MSearch(_ context.Context, ops []bulk.MultiOp, _ ...bulk.Opt) ([]bulk.MsearchResponseItem, error) {
	items := make([]bulk.MsearchResponseItem, len(ops))
	var requestErr error
	for i, op := range ops {
		policyID, err := searchedPolicyID(op.Body)
		if err != nil {
			return nil, err
		}
		item, ok := b.items[policyID]
		if !ok {
			requestErr = errRequestFailed
		}
		items[i] = item
	}
	return items, requestErr
}

// searchedPolicyID returns the policy ID of a query for the latest revision of one policy.
func searchedPolicyID(query []byte) (string, error) {
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
	if err := json.Unmarshal(query, &got); err != nil {
		return "", err
	}
	if len(got.Query.Bool.Filter) != 1 {
		return "", fmt.Errorf("got %d filters, want 1", len(got.Query.Bool.Filter))
	}
	return got.Query.Bool.Filter[0].Term.PolicyID, nil
}

func TestQueryLatestPoliciesByID(t *testing.T) {
	bulker := &policyMSearchBulk{
		items: map[string]bulk.MsearchResponseItem{
			"policy-a": { //nolint:goconst // fixture policy ID
				Status: http.StatusOK,
				Aggregations: map[string]es.Aggregation{
					FieldPolicyID: {
						Buckets: []es.Bucket{{
							Key: "policy-a",
							Aggregations: map[string]es.HitsT{
								FieldRevisionIdx: {
									Hits: []es.HitT{{
										Source: []byte(`{"policy_id":"policy-a","revision_idx":2}`),
									}},
								},
							},
						}},
					},
				},
			},
			"policy-b": { //nolint:goconst // fixture policy ID
				Status: http.StatusOK,
				Aggregations: map[string]es.Aggregation{
					FieldPolicyID: {
						Buckets: []es.Bucket{{
							Key: "policy-b",
							Aggregations: map[string]es.HitsT{
								FieldRevisionIdx: {
									Hits: []es.HitT{{
										Source: []byte(`{"policy_id":"policy-b","revision_idx":1}`),
									}},
								},
							},
						}},
					},
				},
			},
			"malformed-policy": { //nolint:goconst // fixture policy ID
				Status: http.StatusOK,
				Aggregations: map[string]es.Aggregation{
					FieldPolicyID: {
						Buckets: []es.Bucket{{
							Key: "malformed-policy",
							Aggregations: map[string]es.HitsT{
								FieldRevisionIdx: {
									Hits: []es.HitT{{
										Source: []byte(`{"policy_id":"malformed-policy","revision_idx":1,"data":"not an object"}`),
									}},
								},
							},
						}},
					},
				},
			},
			"timed-out-policy": { //nolint:goconst // fixture policy ID
				Status: http.StatusGatewayTimeout,
				Error: json.RawMessage(`{
					"root_cause": [{"type": "timeout_exception", "reason": "timed out"}],
					"type": "timeout_exception",
					"reason": "timed out"
				}`),
			},
			"missing-policy": { //nolint:goconst // fixture policy ID
				Status: http.StatusOK,
				Aggregations: map[string]es.Aggregation{
					FieldPolicyID: {Buckets: []es.Bucket{}},
				},
			},
			`policy"}]}} , "x": "y`: { //nolint:goconst // fixture policy ID
				Status: http.StatusOK,
				Aggregations: map[string]es.Aggregation{
					FieldPolicyID: {Buckets: []es.Bucket{}},
				},
			},
		},
	}

	tests := []struct {
		name         string
		policyIDs    []string
		wantPolicies []model.Policy
		wantErrs     []error
	}{
		{
			name:      "the latest revision of a policy is returned",
			policyIDs: []string{"policy-a"},
			wantPolicies: []model.Policy{
				{PolicyID: "policy-a", RevisionIdx: 2},
			},
		},
		{
			name:      "valid policies are returned when other policies fail",
			policyIDs: []string{"policy-a", "failed-policy", "malformed-policy", "timed-out-policy", "policy-b"},
			wantPolicies: []model.Policy{
				{PolicyID: "policy-a", RevisionIdx: 2},
				{PolicyID: "policy-b", RevisionIdx: 1},
			},
			wantErrs: []error{errRequestFailed, ErrInvalidPolicy, es.ErrTimeout},
		},
		{
			name:         "no policy is returned for a policy that does not exist",
			policyIDs:    []string{"missing-policy"},
			wantPolicies: []model.Policy{},
		},
		{
			name:         "query injection through the policy ID is prevented",
			policyIDs:    []string{`policy"}]}} , "x": "y`},
			wantPolicies: []model.Policy{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policies, err := QueryLatestPoliciesByID(t.Context(), bulker, tc.policyIDs)
			if len(tc.wantErrs) == 0 {
				require.NoError(t, err)
			}
			for _, wantErr := range tc.wantErrs {
				require.ErrorIs(t, err, wantErr)
			}
			assert.ElementsMatch(t, tc.wantPolicies, policies)
		})
	}
}

func TestQueryLatestPoliciesByIDRejectedDispatch(t *testing.T) {
	bulker := ftesting.NewMockBulk()
	bulker.On("MSearch", mock.Anything, mock.Anything, mock.Anything).Return(nil, bulk.ErrTooManyBulkDispatches)

	policies, err := QueryLatestPoliciesByID(t.Context(), bulker, []string{"policy-a"})
	require.ErrorIs(t, err, bulk.ErrTooManyBulkDispatches)
	assert.Empty(t, policies)
}
