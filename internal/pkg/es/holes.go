// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package es

import "github.com/elastic/fleet-server/v7/internal/pkg/sqn"

func HasHoles(checkpoint sqn.SeqNo, hits []HitT) bool {
	sz := len(hits)
	if sz == 0 {
		return false
	}

	// Check if the hole is in the beginning of hits
	seqNo := checkpoint.Value()
	if seqNo != sqn.UndefinedSeqNo && (hits[0].SeqNo-seqNo) > 1 {
		return true
	}

	// No holes in the beginning, check if size <= 1 then there is no holes
	if sz <= 1 {
		return false
	}

	// Set initial seqNo value from the last hit in the array
	seqNo = hits[sz-1].SeqNo

	// Iterate from the end since that's where it more likely to have holes
	for i := sz - 2; i >= 0; i-- {
		if (seqNo - hits[i].SeqNo) > 1 {
			return true
		}
		seqNo = hits[i].SeqNo
	}
	return false
}
