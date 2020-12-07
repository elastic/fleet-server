// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

// Indices names
const (
	FleetActions = ".fleet-actions"
	FleetAgents  = ".fleet-agents"
)

// Query fields
const (
	FieldSeqNo  = "_seq_no"
	FieldSource = "_source"
	FieldId     = "_id"

	FieldMaxSeqNo = "max_seq_no"
)

// Public constants
const (
	UndefinedSeqNo = -1
)

// Private constants
const (
	defaultSeqNo     = UndefinedSeqNo
	seqNoPrimaryTerm = "seq_no_primary_term"
)
