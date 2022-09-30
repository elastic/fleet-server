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
	FieldID     = "_id"

	FieldMaxSeqNo    = "max_seq_no"
	FieldActionSeqNo = "action_seq_no"

	FieldActionID                      = "action_id"
	FieldAgent                         = "agent"
	FieldAgentVersion                  = "version"
	FieldCoordinatorIdx                = "coordinator_idx"
	FieldLastCheckin                   = "last_checkin"
	FieldLastCheckinStatus             = "last_checkin_status"
	FieldLastCheckinMessage            = "last_checkin_message"
	FieldLocalMetadata                 = "local_metadata"
	FieldPolicyCoordinatorIdx          = "policy_coordinator_idx"
	FieldPolicyID                      = "policy_id"
	FieldPolicyOutputAPIKey            = "api_key"
	FieldPolicyOutputAPIKeyID          = "api_key_id"
	FieldPolicyOutputPermissionsHash   = "permissions_hash"
	FieldPolicyOutputToRetireAPIKeyIDs = "to_retire_api_key_ids" //nolint:gosec // false positive
	FieldPolicyRevisionIdx             = "policy_revision_idx"
	FieldRevisionIdx                   = "revision_idx"
	FieldUnenrolledReason              = "unenrolled_reason"
	FieldType                          = "type"

	FieldActive           = "active"
	FieldUpdatedAt        = "updated_at"
	FieldUnenrolledAt     = "unenrolled_at"
	FieldUpgradedAt       = "upgraded_at"
	FieldUpgradeStartedAt = "upgrade_started_at"
	FieldUpgradeStatus    = "upgrade_status"

	FieldDecodedSha256 = "decoded_sha256"
	FieldIdentifier    = "identifier"
)

// Private constants
const (
	defaultSeqNo     = sqn.UndefinedSeqNo
	seqNoPrimaryTerm = "seq_no_primary_term"
)
