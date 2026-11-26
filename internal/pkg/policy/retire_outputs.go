// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package policy

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/rs/zerolog"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger/ecs"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/secret"
)

// RetireRemovedOutputs retires the API keys of all agent outputs when the policy has
// no output with API keys left, e.g. when it switched to logstash or kafka. The keys
// are invalidated immediately, as there is no remaining output to park them on until ack.
// Otherwise, removed outputs are retired while preparing the remaining outputs, see
// retireRemovedOutputs.
func RetireRemovedOutputs(ctx context.Context, zlog zerolog.Logger, bulker bulk.Bulk, agent *model.Agent, outputMap map[string]map[string]any) error {
	if len(agent.Outputs) == 0 {
		return nil
	}
	for _, output := range outputMap {
		if hasAPIKeys(output) {
			return nil
		}
	}

	names := slices.Sorted(maps.Keys(agent.Outputs))

	retiredAt := time.Now().UTC().Format(time.RFC3339)
	toRetire := make([]model.ToRetireAPIKeyIdsItems, 0, len(names))
	for _, name := range names {
		out := agent.Outputs[name]
		toRetire = append(toRetire, out.ToRetireAPIKeyIds...)
		if out.APIKeyID == "" {
			continue
		}
		zlog.Info().Str(ecs.APIKeyID, out.APIKeyID).Str(ecs.PolicyOutputName, name).Msg("Output removed, retiring API key")
		toRetire = append(toRetire, retirementRecord(name, out, retiredAt))
	}
	InvalidateAPIKeys(ctx, zlog, bulker, toRetire, "")
	DeleteRetiredSecrets(ctx, zlog, bulker, toRetire)

	for _, name := range names {
		body, err := renderRemoveOutputPainlessScript(name)
		if err != nil {
			return fmt.Errorf("could not create request body to update agent: %w", err)
		}
		if err := bulker.Update(ctx, dl.FleetAgents, agent.Id, body, bulk.WithRefresh(), bulk.WithRetryOnConflict(3)); err != nil {
			zlog.Error().Err(err).Msg("fail update agent record")
			return fmt.Errorf("fail update agent record: %w", err)
		}
		delete(agent.Outputs, name)
	}
	return nil
}

// retirementRecord returns the record used to retire the active API key of an agent output.
func retirementRecord(outputName string, out *model.PolicyOutput, retiredAt string) model.ToRetireAPIKeyIdsItems {
	record := model.ToRetireAPIKeyIdsItems{
		ID:         out.APIKeyID,
		RetiredAt:  retiredAt,
		Output:     outputName,
		OutputType: out.Type,
	}
	if secretID, ok := secret.ParseSecretReference(out.APIKey); ok {
		record.SecretID = secretID
	}
	return record
}

// hasAPIKeys reports whether the policy output may have per-agent API keys. Outputs
// without a type are assumed to have them, so that their keys are never retired by mistake.
func hasAPIKeys(output map[string]any) bool {
	t, _ := output[FieldOutputType].(string)
	return t == "" || t == OutputTypeElasticsearch || t == OutputTypeRemoteElasticsearch || t == OutputTypeOTLP
}

// InvalidateAPIKeys retires the given API keys against the correct cluster.
//
// Each item's Output field names the output the key belongs to.
// An empty Output routes directly to the primary cluster (bulk).
// A non-empty Output triggers a remote-bulker lookup: GetBulker is tried first (hot path),
// then CreateAndGetBulker via QueryOutputFromPolicy (cold/restart path). If neither resolves
// a bulker, the primary cluster is used as a fallback — correct for local outputs (elasticsearch,
// otlp) and benign for unreachable remote outputs (primary returns "not found" rather than
// silently dropping the request).
//
// This mirrors the fail-safe pattern in updateAPIKey, which starts with the primary bulker
// and only upgrades to a remote one when available.
func InvalidateAPIKeys(ctx context.Context, zlog zerolog.Logger, bulk bulk.Bulk, toRetireAPIKeyIDs []model.ToRetireAPIKeyIdsItems, skip string) {
	ids := make([]string, 0, len(toRetireAPIKeyIDs))
	remoteIds := make(map[string][]string)
	for _, k := range toRetireAPIKeyIDs {
		if k.ID == skip || k.ID == "" {
			continue
		}
		// Route by output_type when available. OTLP keys are always on the primary cluster
		// so they go directly into the primary bucket. All other types — including
		// "elasticsearch", which the agent doc uses for both local and remote ES after
		// normalization — stay on the name-based path so existing routing is preserved
		// for records that predate this field or that cannot be distinguished from remote ES.
		switch k.OutputType {
		case OutputTypeOTLP:
			ids = append(ids, k.ID)
		default:
			if k.Output != "" {
				if remoteIds[k.Output] == nil {
					remoteIds[k.Output] = make([]string, 0)
				}
				remoteIds[k.Output] = append(remoteIds[k.Output], k.ID)
			} else {
				ids = append(ids, k.ID)
			}
		}
	}
	if len(ids) > 0 {
		zlog.Info().Strs("fleet.policy.apiKeyIDsToRetire", ids).Msg("Invalidate old API keys")
		if err := bulk.APIKeyInvalidate(ctx, ids...); err != nil {
			zlog.Warn().Err(err).Strs("ids", ids).Msg("Failed to invalidate API keys. API keys will be orphaned.")
		}
	}
	// using remote es bulker to invalidate api key
	for outputName, outputIds := range remoteIds {
		outputBulk := bulk.GetBulker(outputName)
		usedPrimaryFallback := false

		var outputPolicy *model.Policy
		if outputBulk == nil {
			// read output config from .fleet-policies, not filtering by policy id as agent could be reassigned
			var err error
			outputPolicy, err = dl.QueryOutputFromPolicy(ctx, bulk, outputName)
			if err != nil || outputPolicy == nil {
				zlog.Warn().Err(err).Str(ecs.PolicyOutputName, outputName).Any("ids", outputIds).Msg("Output policy not found, falling back to primary cluster for key invalidation")
			} else {
				outputBulk, _, err = bulk.CreateAndGetBulker(ctx, zlog, outputName, outputPolicy.Data.Outputs)
				if err != nil {
					zlog.Warn().Err(err).Str(ecs.PolicyOutputName, outputName).Any("ids", outputIds).Msg("Failed to recreate output bulker, falling back to primary cluster for key invalidation")
				}
			}
		}
		if outputBulk == nil {
			if outputPolicy != nil && outputPolicy.Data.Outputs[outputName]["type"] == OutputTypeRemoteElasticsearch {
				zlog.Warn().Str(ecs.PolicyOutputName, outputName).Any("ids", outputIds).
					Msg("Cannot invalidate remote ES API keys: remote cluster unreachable, API keys will be orphaned")
				continue
			}
			outputBulk = bulk
			usedPrimaryFallback = true
		}
		if err := outputBulk.APIKeyInvalidate(ctx, outputIds...); err != nil {
			zlog.Warn().Err(err).Strs("ids", outputIds).Str(ecs.PolicyOutputName, outputName).
				Bool("fallback_to_primary", usedPrimaryFallback).
				Msg("Failed to invalidate output API keys. API keys will be orphaned.")
		}
	}
}

// DeleteRetiredSecrets deletes the fleet secrets of the given retired API keys.
func DeleteRetiredSecrets(ctx context.Context, zlog zerolog.Logger, bulk bulk.Bulk, toRetireAPIKeyIDs []model.ToRetireAPIKeyIdsItems) {
	for _, k := range toRetireAPIKeyIDs {
		if k.SecretID == "" {
			continue
		}
		if err := bulk.DeleteSecret(ctx, k.SecretID); err != nil {
			zlog.Warn().Err(err).Str("secret_id", k.SecretID).Msg("Failed to delete retired output API key secret")
		}
	}
}
