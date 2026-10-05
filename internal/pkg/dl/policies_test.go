// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dl

import (
	"context"
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
