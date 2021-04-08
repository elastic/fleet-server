// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import "github.com/elastic/fleet-server/v7/internal/pkg/sqn"

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

	FieldActionId                    = "action_id"
	FieldPolicyId                    = "policy_id"
	FieldRevisionIdx                 = "revision_idx"
	FieldCoordinatorIdx              = "coordinator_idx"
	FieldLastCheckin                 = "last_checkin"
	FieldLocalMetadata               = "local_metadata"
	FieldPolicyRevisionIdx           = "policy_revision_idx"
	FieldPolicyCoordinatorIdx        = "policy_coordinator_idx"
	FieldDefaultApiKey               = "default_api_key"
	FieldDefaultApiKeyId             = "default_api_key_id"
	FieldPolicyOutputPermissionsHash = "policy_output_permissions_hash"

	FieldActive           = "active"
	FieldUpdatedAt        = "updated_at"
	FieldUnenrolledAt     = "unenrolled_at"
	FieldUpgradedAt       = "upgraded_at"
	FieldUpgradeStartedAt = "upgrade_started_at"

	FieldDecodedSha256 = "decoded_sha256"
	FieldIdentifier    = "identifier"
)

// Private constants
const (
	defaultSeqNo     = sqn.UndefinedSeqNo
	seqNoPrimaryTerm = "seq_no_primary_term"
)
