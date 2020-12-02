// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package esutil

import "encoding/json"

type Hit struct {
	ID     string          `json:"_id"`
	SeqNo  uint64          `json:"_seq_no"`
	Source json.RawMessage `json:"_source"`
}

type Result struct {
	Hits []Hit `json:"hits"`
}

type SearchResponse struct {
	Result Result `json:"hits"`
}
