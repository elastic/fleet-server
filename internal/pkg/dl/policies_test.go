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

// fakePolicySearchBulk answers the policy searches from fixed data as Elasticsearch would.
type fakePolicySearchBulk struct {
	bulk.Bulk
<<<<<<< HEAD
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
=======
	items            map[string]bulk.MsearchResponseItem
	defaultPolicyIDs []string
}
>>>>>>> 39eeea5 (Load only the needed policies in Fleet Server health checks and enrollments (#8224))

		var got, all map[string]any
		require.NoError(t, json.Unmarshal(bulker.query, &got))
		require.NoError(t, json.Unmarshal(tmplQueryLatestPolicies, &all))

<<<<<<< HEAD
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
=======
func (b *fakePolicySearchBulk) Search(_ context.Context, _ string, query []byte, _ ...bulk.Opt) (*es.ResultT, error) {
	policyIDs, err := searchedPolicyIDs(query)
	if err != nil {
		return nil, err
	}
	// Without policy IDs it is the search for the IDs of the policies that were the default.
	if policyIDs == nil {
		policyIDs = b.defaultPolicyIDs
		buckets := make([]es.Bucket, len(policyIDs))
		for i, policyID := range policyIDs {
			buckets[i] = es.Bucket{Key: policyID}
		}
		res := &es.ResultT{Aggregations: map[string]es.Aggregation{FieldPolicyID: {Buckets: buckets}}}
		return res, nil
	}
	var got struct {
		Size int `json:"size"`
	}
	if err := json.Unmarshal(query, &got); err != nil {
		return nil, err
	}
	// The search for the latest revision of one policy returns its hit.
	if got.Size == 1 {
		item := b.items[policyIDs[0]]
		if item.Status != http.StatusOK {
			return nil, es.TranslateError(item.Status, item.Error)
		}
		var hits []es.HitT
		for _, bucket := range item.Aggregations[FieldPolicyID].Buckets {
			hits = append(hits, bucket.Aggregations[FieldRevisionIdx].Hits...)
		}
		res := &es.ResultT{Hits: hits}
		return res, nil
	}
	var buckets []es.Bucket
	for _, policyID := range policyIDs {
		item := b.items[policyID]
		if item.Status != http.StatusOK {
			return nil, es.TranslateError(item.Status, item.Error)
		}
		// The search for the latest revision of several policies returns only their default flags.
		var flags struct {
			PolicyID           string `json:"policy_id"`
			RevisionIdx        int64  `json:"revision_idx"`
			DefaultFleetServer bool   `json:"default_fleet_server"`
		}
		hit := item.Aggregations[FieldPolicyID].Buckets[0].Aggregations[FieldRevisionIdx].Hits[0]
		if err := json.Unmarshal(hit.Source, &flags); err != nil {
			return nil, err
		}
		if hit.Source, err = json.Marshal(flags); err != nil {
			return nil, err
		}
		buckets = append(buckets, latestRevisionAggs(hit)[FieldPolicyID].Buckets...)
	}
	res := &es.ResultT{Aggregations: map[string]es.Aggregation{FieldPolicyID: {Buckets: buckets}}}
	return res, nil
}

func (b *fakePolicySearchBulk) MSearch(_ context.Context, ops []bulk.MultiOp, _ ...bulk.Opt) ([]bulk.MsearchResponseItem, error) {
	items := make([]bulk.MsearchResponseItem, len(ops))
	var requestErr error
	for i, op := range ops {
		policyIDs, err := searchedPolicyIDs(op.Body)
		if err != nil {
			return nil, err
		}
		if len(policyIDs) != 1 {
			return nil, fmt.Errorf("got %d policy IDs, want 1", len(policyIDs))
		}
		item, ok := b.items[policyIDs[0]]
		if !ok {
			requestErr = errRequestFailed
		}
		items[i] = item
	}
	return items, requestErr
}

func searchedPolicyIDs(query []byte) ([]string, error) {
	var got struct {
		Query struct {
			Bool struct {
				Filter []struct {
					Term struct {
						PolicyID string `json:"policy_id"`
					} `json:"term"`
					Terms struct {
						PolicyID []string `json:"policy_id"`
					} `json:"terms"`
				} `json:"filter"`
			} `json:"bool"`
		} `json:"query"`
	}
	if err := json.Unmarshal(query, &got); err != nil {
		return nil, err
	}
	var policyIDs []string
	for _, filter := range got.Query.Bool.Filter {
		if filter.Term.PolicyID != "" {
			policyIDs = append(policyIDs, filter.Term.PolicyID)
		}
		policyIDs = append(policyIDs, filter.Terms.PolicyID...)
	}
	return policyIDs, nil
}

func TestQueryLatestPolicy(t *testing.T) {
	bulker := &fakePolicySearchBulk{
		items: map[string]bulk.MsearchResponseItem{
			"policy-a": {
				Status: http.StatusOK,
				Aggregations: latestRevisionAggs(es.HitT{
					Source: []byte(`{"policy_id":"policy-a","revision_idx":2}`),
				}),
			},
			"default-policy": {
				Status: http.StatusOK,
				Aggregations: latestRevisionAggs(es.HitT{
					Source: []byte(`{"policy_id":"default-policy","revision_idx":2,"default_fleet_server":true}`),
				}),
			},
		},
		defaultPolicyIDs: []string{"default-policy"},
	}

	tests := []struct {
		name       string
		policyID   string
		opts       []Option
		wantPolicy model.Policy
		wantErr    error
	}{
		{
			name:       "a policy is found by its ID",
			policyID:   "policy-a",
			wantPolicy: model.Policy{PolicyID: "policy-a", RevisionIdx: 2},
		},
		{
			name:       "the default policy is found when the ID is empty and the fallback is set",
			policyID:   "",
			opts:       []Option{WithDefaultFleetServerFallback()},
			wantPolicy: model.Policy{PolicyID: "default-policy", RevisionIdx: 2, DefaultFleetServer: true},
		},
		{
			name:    "no policy is found when the ID is empty and the fallback is not set",
			wantErr: ErrNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := QueryLatestPolicy(t.Context(), bulker, tc.policyID, tc.opts...)
			if tc.wantErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tc.wantErr)
			}
			assert.Equal(t, tc.wantPolicy, policy)
		})
	}
}

func TestQueryLatestPolicyByID(t *testing.T) {
	bulker := &fakePolicySearchBulk{
		items: map[string]bulk.MsearchResponseItem{
			"policy-a": {
				Status: http.StatusOK,
				Aggregations: latestRevisionAggs(es.HitT{
					Source: []byte(`{"policy_id":"policy-a","revision_idx":2}`),
				}),
			},
			"missing-policy": {
				Status: http.StatusOK,
				Aggregations: map[string]es.Aggregation{
					FieldPolicyID: {Buckets: []es.Bucket{}},
				},
			},
			"timed-out-policy": {
				Status: http.StatusGatewayTimeout,
				Error: json.RawMessage(`{
					"root_cause": [{"type": "timeout_exception", "reason": "timed out"}],
					"type": "timeout_exception",
					"reason": "timed out"
				}`),
			},
		},
	}

	tests := []struct {
		name       string
		policyID   string
		wantPolicy model.Policy
		wantErr    error
	}{
		{
			name:       "the policy that the search finds is returned",
			policyID:   "policy-a",
			wantPolicy: model.Policy{PolicyID: "policy-a", RevisionIdx: 2},
		},
		{
			name:     "a policy that does not exist is not found",
			policyID: "missing-policy",
			wantErr:  ErrNotFound,
		},
		{
			name:     "the error of a failed search is returned",
			policyID: "timed-out-policy",
			wantErr:  es.ErrTimeout,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := QueryLatestPolicyByID(t.Context(), bulker, tc.policyID)
			if tc.wantErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tc.wantErr)
			}
			assert.Equal(t, tc.wantPolicy, policy)
		})
	}
}

func TestQueryDefaultFleetServerPolicy(t *testing.T) {
	items := map[string]bulk.MsearchResponseItem{
		"default-policy": {
			Status: http.StatusOK,
			Aggregations: latestRevisionAggs(es.HitT{
				Source: []byte(`{"policy_id":"default-policy","revision_idx":2,"default_fleet_server":true,"data":{"outputs":{"o":{"type":"elasticsearch"}}}}`),
			}),
		},
		"old-default-policy": {
			Status: http.StatusOK,
			Aggregations: latestRevisionAggs(es.HitT{
				Source: []byte(`{"policy_id":"old-default-policy","revision_idx":5,"default_fleet_server":false}`),
			}),
		},
		"timed-out-policy": {
			Status: http.StatusGatewayTimeout,
			Error: json.RawMessage(`{
					"root_cause": [{"type": "timeout_exception", "reason": "timed out"}],
					"type": "timeout_exception",
					"reason": "timed out"
				}`),
		},
	}

	tests := []struct {
		name             string
		defaultPolicyIDs []string
		wantPolicy       model.Policy
		wantErr          error
	}{
		{
			name:             "the default policy is returned when other policies were the default before",
			defaultPolicyIDs: []string{"old-default-policy", "default-policy"},
			wantPolicy: model.Policy{
				PolicyID:           "default-policy",
				RevisionIdx:        2,
				DefaultFleetServer: true,
				Data:               &model.PolicyData{Outputs: map[string]map[string]any{"o": {FiledType: testES}}},
			},
		},
		{
			name:             "no default policy is found when only earlier revisions are the default",
			defaultPolicyIDs: []string{"old-default-policy"},
			wantErr:          ErrNotFound,
		},
		{
			name:    "no default policy is found when no policy was the default",
			wantErr: ErrNotFound,
		},
		{
			name:             "the error of a failed search for a policy that was the default is returned",
			defaultPolicyIDs: []string{"default-policy", "timed-out-policy"},
			wantErr:          es.ErrTimeout,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bulker := &fakePolicySearchBulk{
				items:            items,
				defaultPolicyIDs: tc.defaultPolicyIDs,
			}
			policy, err := QueryDefaultFleetServerPolicy(t.Context(), bulker)
			if tc.wantErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tc.wantErr)
			}
			assert.Equal(t, tc.wantPolicy, policy)
		})
	}
}

func TestQueryDefaultFleetServerPolicyLatestRevision(t *testing.T) {
	defaultPolicyIDs := &es.ResultT{
		Aggregations: map[string]es.Aggregation{FieldPolicyID: {Buckets: []es.Bucket{{Key: "default-policy"}}}},
	}
	defaultFlags := &es.ResultT{
		Aggregations: latestRevisionAggs(es.HitT{
			Source: []byte(`{"policy_id":"default-policy","revision_idx":2,"default_fleet_server":true}`),
		}),
	}

	tests := []struct {
		name       string
		latest     *es.ResultT
		latestErr  error
		wantPolicy model.Policy
		wantErr    error
	}{
		{
			name: "the latest revision is returned when it is the default",
			latest: &es.ResultT{Hits: []es.HitT{{
				Source: []byte(`{"policy_id":"default-policy","revision_idx":3,"default_fleet_server":true}`),
			}}},
			wantPolicy: model.Policy{
				PolicyID:           "default-policy",
				RevisionIdx:        3,
				DefaultFleetServer: true,
			},
		},
		{
			name: "no default policy is found when the latest revision is not the default",
			latest: &es.ResultT{Hits: []es.HitT{{
				Source: []byte(`{"policy_id":"default-policy","revision_idx":3,"default_fleet_server":false}`),
			}}},
			wantErr: ErrNotFound,
		},
		{
			name:      "the error of a failed search for the latest revision is returned",
			latestErr: es.ErrTimeout,
			wantErr:   es.ErrTimeout,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bulker := ftesting.NewMockBulk()
			bulker.On("Search", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(defaultPolicyIDs, nil).Once()
			bulker.On("Search", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(defaultFlags, nil).Once()
			bulker.On("Search", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(tc.latest, tc.latestErr).Once()

			policy, err := QueryDefaultFleetServerPolicy(t.Context(), bulker)
			if tc.wantErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tc.wantErr)
			}
			assert.Equal(t, tc.wantPolicy, policy)
		})
	}
}

func TestQueryLatestPoliciesByID(t *testing.T) {
	bulker := &fakePolicySearchBulk{
		items: map[string]bulk.MsearchResponseItem{
			"policy-a": {
				Status: http.StatusOK,
				Aggregations: latestRevisionAggs(es.HitT{
					Source: []byte(`{"policy_id":"policy-a","revision_idx":2}`),
				}),
			},
			"policy-b": {
				Status: http.StatusOK,
				Aggregations: latestRevisionAggs(es.HitT{
					Source: []byte(`{"policy_id":"policy-b","revision_idx":1}`),
				}),
			},
			"malformed-policy": {
				Status: http.StatusOK,
				Aggregations: latestRevisionAggs(es.HitT{
					Source: []byte(`{"policy_id":"malformed-policy","revision_idx":1,"data":"not an object"}`),
				}),
			},
			"timed-out-policy": {
				Status: http.StatusGatewayTimeout,
				Error: json.RawMessage(`{
					"root_cause": [{"type": "timeout_exception", "reason": "timed out"}],
					"type": "timeout_exception",
					"reason": "timed out"
				}`),
			},
			"missing-policy": {
				Status: http.StatusOK,
				Aggregations: map[string]es.Aggregation{
					FieldPolicyID: {Buckets: []es.Bucket{}},
				},
			},
			`policy"}]}} , "x": "y`: {
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

func TestQueryLatestPoliciesByIDSharesStrings(t *testing.T) {
	query := strings.Repeat("SELECT name, path FROM processes WHERE ", 4)
	policyIDs := make([]string, 2)
	bulker := &fakePolicySearchBulk{items: map[string]bulk.MsearchResponseItem{}}
	for i := range policyIDs {
		policyIDs[i] = fmt.Sprintf("policy-%d", i)
		bulker.items[policyIDs[i]] = bulk.MsearchResponseItem{
			Status: http.StatusOK,
			Aggregations: latestRevisionAggs(es.HitT{
				ID:     fmt.Sprintf("doc-%d", i),
				SeqNo:  int64(10 + i),
				Source: policySource(fmt.Sprintf(`[{"query":%q}]`, query)),
			}),
		}
	}

	policies, err := QueryLatestPoliciesByID(t.Context(), bulker, policyIDs)
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

// policySource returns a policy document whose inputs are the given JSON array.
func policySource(inputs string) []byte {
	return fmt.Appendf(nil, `{"policy_id":"p","revision_idx":3,"@timestamp":"2026-01-01T00:00:00Z","namespaces":["a"],`+
		`"data":{"id":"p","revision":3,"outputs":{"o":{"type":"elasticsearch","hosts":["h"]}},"agent":{"x":{"y":1}},"inputs":%s}}`, inputs)
}

func TestQueryLatestPoliciesByIDRejectedDispatch(t *testing.T) {
	bulker := ftesting.NewMockBulk()
	bulker.On("MSearch", mock.Anything, mock.Anything, mock.Anything).Return(nil, bulk.ErrTooManyBulkDispatches)

	policies, err := QueryLatestPoliciesByID(t.Context(), bulker, []string{"policy-a"})
	require.ErrorIs(t, err, bulk.ErrTooManyBulkDispatches)
	assert.Empty(t, policies)
>>>>>>> 39eeea5 (Load only the needed policies in Fleet Server health checks and enrollments (#8224))
}

// searchRecorder records the queries of Search in order.
type searchRecorder struct {
	bulk.Bulk
	queries []string
}

func (b *searchRecorder) Search(ctx context.Context, index string, query []byte, opts ...bulk.Opt) (*es.ResultT, error) {
	b.queries = append(b.queries, string(query))
	return b.Bulk.Search(ctx, index, query, opts...)
}

func TestQueryDefaultFleetServerPolicySearches(t *testing.T) {
	bulker := &searchRecorder{
		Bulk: &fakePolicySearchBulk{
			items: map[string]bulk.MsearchResponseItem{
				"default-policy": {
					Status: http.StatusOK,
					Aggregations: latestRevisionAggs(es.HitT{
						Source: []byte(`{"policy_id":"default-policy","revision_idx":2,"default_fleet_server":true}`),
					}),
				},
				"old-default-policy": {
					Status: http.StatusOK,
					Aggregations: latestRevisionAggs(es.HitT{
						Source: []byte(`{"policy_id":"old-default-policy","revision_idx":5,"default_fleet_server":false}`),
					}),
				},
			},
			defaultPolicyIDs: []string{"old-default-policy", "default-policy"},
		},
	}

	policy, err := QueryDefaultFleetServerPolicy(t.Context(), bulker)
	require.NoError(t, err)
	assert.Equal(t, "default-policy", policy.PolicyID)

	require.Len(t, bulker.queries, 3)
	assert.Contains(t, bulker.queries[0], `{"term":{"default_fleet_server":true}}`, "only the policies that were the default are candidates")
	assert.Contains(t, bulker.queries[1], `"_source":{"includes":["policy_id","revision_idx","default_fleet_server"]}`, "the candidates are searched without their content")
}

func latestRevisionAggs(hit es.HitT) map[string]es.Aggregation {
	return map[string]es.Aggregation{
		FieldPolicyID: {
			Buckets: []es.Bucket{{
				Aggregations: map[string]es.HitsT{
					FieldRevisionIdx: {
						Hits: []es.HitT{hit},
					},
				},
			}},
		},
	}
}
