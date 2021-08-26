// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// +build !integration

package monitor

import (
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/google/go-cmp/cmp"
)

// Sanity test of interal check if hits lits has holes
func TestHashHoles(t *testing.T) {

	tests := []struct {
		Name     string
		Hits     []es.HitT
		HasHoles bool
	}{
		{
			Name: "nil",
			Hits: genHitsSequence(nil),
		},
		{
			Name: "empty",
			Hits: genHitsSequence([]int64{}),
		},
		{
			Name: "one",
			Hits: genHitsSequence([]int64{1}),
		},
		{
			Name: "two",
			Hits: genHitsSequence([]int64{1, 2}),
		},
		{
			Name:     "two with hole",
			Hits:     genHitsSequence([]int64{1, 3}),
			HasHoles: true,
		},
		{
			Name:     "holed",
			Hits:     genHitsSequence([]int64{2, 3, 4, 6}),
			HasHoles: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			diff := cmp.Diff(tc.HasHoles, hasHoles(tc.Hits))
			if diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func genHitsSequence(seq []int64) []es.HitT {
	if seq == nil {
		return nil
	}

	hits := make([]es.HitT, 0, len(seq))
	for _, s := range seq {
		hits = append(hits, es.HitT{
			SeqNo: s,
		})
	}
	return hits
}
