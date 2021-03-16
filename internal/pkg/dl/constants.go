// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

// Indices names
const (
	FleetActions           = ".fleet-actions"
	FleetActionsResults    = ".fleet-actions-results"
	FleetAgents            = ".fleet-agents"
	FleetArtifacts         = ".fleet-artifacts"
	FleetEnrollmentAPIKeys = ".fleet-enrollment-api-keys"
	FleetPolicies          = ".fleet-policies"
	FleetPoliciesLeader    = ".fleet-policies-leader"
	FleetServers           = ".fleet-servers"
)

// Query fields
const (
	FieldSeqNo  = "_seq_no"
	FieldSource = "_source"
	FieldId     = "_id"

	FieldMaxSeqNo    = "max_seq_no"
	FieldActionSeqNo = "action_seq_no"

	FieldActionId             = "action_id"
	FieldPolicyId             = "policy_id"
	FieldRevisionIdx          = "revision_idx"
	FieldCoordinatorIdx       = "coordinator_idx"
	FieldPolicyRevisionIdx    = "policy_revision_idx"
	FieldPolicyCoordinatorIdx = "policy_coordinator_idx"

	FieldActive       = "active"
	FieldUpdatedAt    = "updated_at"
	FieldUnenrolledAt = "unenrolled_at"

	FieldDecodedSha256 = "decodedSha256"
	FieldIdentifier    = "identifier"
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
