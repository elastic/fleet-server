// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"go.elastic.co/apm/v2"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger/ecs"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/secret"
	"github.com/elastic/fleet-server/v7/internal/pkg/smap"
)

const (
	OutputTypeElasticsearch       = "elasticsearch"
	OutputTypeRemoteElasticsearch = "remote_elasticsearch"
	OutputTypeLogstash            = "logstash"
	OutputTypeKafka               = "kafka"
	OutputTypeOTLP                = "otlp"

	OTelExporterTypeElasticsearch = "elasticsearch"
)

var (
	ErrNoOutputPerms    = errors.New("output permission sections not found")
	ErrFailInjectAPIKey = errors.New("fail inject api key")
)

type Output struct {
	Name         string
	Type         string
	ServiceToken string
	Role         *RoleT
}

// OutputSecretCandidate identifies a secret whose reference may or may not have
// been committed to an agent document after an ambiguous update failure.
type OutputSecretCandidate struct {
	AgentID    string
	OutputName string
	SecretID   string
	SecretRef  string
}

// OutputSecretCandidateCollector accepts secrets for out-of-band reconciliation.
type OutputSecretCandidateCollector interface {
	Add(OutputSecretCandidate) bool
}

type outputPrepareConfig struct {
	secretCandidateCollector OutputSecretCandidateCollector
}

// OutputPrepareOption configures output preparation.
type OutputPrepareOption func(*outputPrepareConfig)

// WithOutputSecretCandidateCollector records secrets created before ambiguous
// agent update failures so they can be reconciled outside the request path.
func WithOutputSecretCandidateCollector(collector OutputSecretCandidateCollector) OutputPrepareOption {
	return func(c *outputPrepareConfig) {
		c.secretCandidateCollector = collector
	}
}

// Prepare prepares the output p to be sent to the elastic-agent
// The agent might be mutated for an elasticsearch output
func (p *Output) Prepare(ctx context.Context, zlog zerolog.Logger, bulker bulk.Bulk, agent *model.Agent, outputMap map[string]map[string]any, opts ...OutputPrepareOption) error {
	cfg := outputPrepareConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}

	span, ctx := apm.StartSpan(ctx, "prepareOutput", "process")
	defer span.End()
	span.Context.SetLabel("output_type", p.Type)
	zlog = zlog.With().
		Str(ecs.AgentID, agent.Id).
		Str(ecs.PolicyOutputName, p.Name).Logger()

	switch p.Type {
	case OutputTypeElasticsearch:
		zlog.Debug().Msg("preparing elasticsearch output")
		if err := p.prepareElasticsearch(ctx, zlog, bulker, bulker, agent, outputMap, false, cfg.secretCandidateCollector); err != nil {
			return fmt.Errorf("failed to prepare elasticsearch output %q: %w", p.Name, err)
		}
	case OutputTypeRemoteElasticsearch:
		zlog.Debug().Msg("preparing remote elasticsearch output")
		newBulker, hasConfigChanged, err := bulker.CreateAndGetBulker(ctx, zlog, p.Name, outputMap)
		if err != nil {
			return err
		}
		// the outputBulker is different for remote ES, it is used to create/update Api keys in the remote ES client
		if err := p.prepareElasticsearch(ctx, zlog, bulker, newBulker, agent, outputMap, hasConfigChanged, cfg.secretCandidateCollector); err != nil {
			return fmt.Errorf("failed to prepare remote elasticsearch output %q: %w", p.Name, err)
		}
	case OutputTypeLogstash:
		zlog.Debug().Msg("preparing logstash output")
		zlog.Info().Msg("no actions required for logstash output preparation")
	case OutputTypeKafka:
		zlog.Debug().Msg("preparing kafka output")
		zlog.Info().Msg("no actions required for kafka output preparation")
	case OutputTypeOTLP:
		zlog.Debug().Msg("preparing OTLP output")
		if err := p.prepareOTLP(ctx, zlog, bulker, agent, outputMap, cfg.secretCandidateCollector); err != nil {
			return fmt.Errorf("failed to prepare OTLP output %q: %w", p.Name, err)
		}
	default:
		zlog.Error().Msgf("unknown output type: %s; skipping preparation", p.Type)
		return fmt.Errorf("encountered unexpected output type while preparing outputs: %s", p.Type)
	}
	return nil
}

func (p *Output) prepareElasticsearch(
	ctx context.Context,
	zlog zerolog.Logger,
	bulker bulk.Bulk,
	outputBulker bulk.Bulk,
	agent *model.Agent,
	outputMap map[string]map[string]any,
	hasConfigChanged bool,
	secretCandidateCollector OutputSecretCandidateCollector) error {
	// The role is required to do api key management
	if p.Role == nil {
		zlog.Error().
			Msg("policy does not contain required output permission section")
		return ErrNoOutputPerms
	}
	if _, ok := outputMap[p.Name]; !ok {
		zlog.Error().Err(ErrFailInjectAPIKey).Msg("Unable to find output in map")
		return ErrFailInjectAPIKey
	}

	output, foundOutput := agent.Outputs[p.Name]
	if !foundOutput {
		if agent.Outputs == nil {
			agent.Outputs = map[string]*model.PolicyOutput{}
		}

		zlog.Debug().Msgf("creating agent.Outputs[%s]", p.Name)
		output = &model.PolicyOutput{}
		agent.Outputs[p.Name] = output
	}

	if err := retireRemovedOutputs(ctx, zlog, bulker, agent, p.Name, outputMap); err != nil {
		return err
	}

	// Determine whether we need to generate an output ApiKey.
	// This is accomplished by comparing the sha2 hash stored in the corresponding
	// output in the agent record with the precalculated sha2 hash of the role.

	// Note: This will need to be updated when doing multi-cluster elasticsearch support
	// Currently, we assume all ES outputs are the same ES fleet-server is connected to.
	needNewKey := false
	needUpdateKey := false
	switch {
	case output.APIKey == "":
		zlog.Debug().Msg("must generate api key as default API key is not present")
		needNewKey = true
	case hasConfigChanged:
		zlog.Debug().Msg("must generate api key as remote output config changed")
		needNewKey = true
	case output.Type != "" && agentDocOutputType(output.Type) != OutputTypeElasticsearch:
		zlog.Debug().Str("persistedType", output.Type).Msg("must generate api key as output type changed")
		needNewKey = true
	case p.Role.Sha2 != output.PermissionsHash:
		// the is actually the OutputPermissionsHash for the default hash. The Agent
		// document on ES does not have OutputPermissionsHash for any other output
		// besides the default one. It seems to me error-prone to rely on the default
		// output permissions hash to generate new API keys for other outputs.
		zlog.Debug().Msg("must update api key as policy output permissions changed")
		needUpdateKey = true
	default:
		zlog.Debug().Msg("policy output permissions are the same")
	}

	if needUpdateKey {
		if err := updateOutputAPIKeyRoles(ctx, zlog, bulker, outputBulker, agent, p.Name, OutputTypeElasticsearch, output, p.Role); err != nil {
			return err
		}
	} else if needNewKey {
		zlog.Debug().
			RawJSON("fleet.policy.roles", p.Role.Raw).
			Str("fleet.policy.default.oldHash", output.PermissionsHash).
			Str("fleet.policy.default.newHash", p.Role.Sha2).
			Msg("Generating a new API key")

		ctx := zlog.WithContext(ctx)
		outputAPIKey, err :=
			generateOutputAPIKey(ctx, outputBulker, agent.Id, p.Name, p.Role.Raw)

		// reporting output health and not returning the error to keep fleet-server running
		if outputAPIKey == nil && p.Type == OutputTypeRemoteElasticsearch {
			if err != nil {
				doc := model.OutputHealth{
					Output:  p.Name,
					State:   client.UnitStateDegraded.String(),
					Message: fmt.Sprintf("remote ES could not create API key due to error: %v", err),
				}
				zerolog.Ctx(ctx).Warn().Err(err).Str(ecs.PolicyOutputName, p.Name).Msg(doc.Message)

				if err := dl.CreateOutputHealth(ctx, bulker, doc); err != nil {
					zlog.Error().Err(err).Str(ecs.PolicyOutputName, p.Name).Msg("error writing output health")
				}
			}

			// replace type remote_elasticsearch with elasticsearch as agent doesn't recognize remote_elasticsearch
			outputMap[p.Name][FieldOutputType] = OutputTypeElasticsearch
			// remove the service token from the agent policy sent to the agent
			delete(outputMap[p.Name], FieldOutputServiceToken)
			return nil
		} else if p.Type == OutputTypeRemoteElasticsearch {
			doc := model.OutputHealth{
				Output:  p.Name,
				State:   client.UnitStateHealthy.String(),
				Message: "",
			}
			if err := dl.CreateOutputHealth(ctx, bulker, doc); err != nil {
				zlog.Error().Err(err).Msg("create output health")
			}
		}
		if err != nil {
			return fmt.Errorf("failed generate output API key: %w", err)
		}

		// When a new keys is generated we need to update the Agent record,
		// this will need to be updated when multiples remote Elasticsearch output
		// are supported.
		zlog.Info().
			Str("fleet.policy.role.hash.sha256", p.Role.Sha2).
			Str(ecs.DefaultOutputAPIKeyID, outputAPIKey.ID).
			Msg("Updating agent record to pick up default output key.")

		if err := persistNewOutputAPIKey(ctx, zlog, bulker, agent, p.Name, OutputTypeElasticsearch, output, p.Role, outputAPIKey, secretCandidateCollector); err != nil {
			return err
		}
	}

	if p.Type == OutputTypeRemoteElasticsearch {

		// replace type remote_elasticsearch with elasticsearch as agent doesn't recognize remote_elasticsearch
		outputMap[p.Name][FieldOutputType] = OutputTypeElasticsearch
		// remove the service token from the agent policy sent to the agent
		delete(outputMap[p.Name], FieldOutputServiceToken)
	}

	// Always insert the `api_key` as part of the output block, this is required
	// because only fleet server knows the api key for the specific agent, if we don't
	// add it the agent will not receive the `api_key` and will not be able to connect
	// to Elasticsearch.
	//
	// We need to investigate allocation with the new LS output, we had optimization
	// in place to reduce number of agent policy allocation when sending the updated
	// agent policy to multiple agents.
	// See: https://github.com/elastic/fleet-server/issues/1301
	apiKey := output.APIKey
	if secretID, ok := secret.ParseSecretReference(apiKey); ok {
		resolved, err := bulker.ReadSecrets(ctx, []string{secretID})
		if err != nil {
			return fmt.Errorf("failed resolving output API key secret: %w", err)
		}
		val, ok := resolved[secretID]
		if !ok || val == "" {
			return fmt.Errorf("output API key secret %q not found", secretID)
		}
		apiKey = val
	}
	outputMap[p.Name]["api_key"] = apiKey
	return nil
}

func (p *Output) prepareOTLP(
	ctx context.Context,
	zlog zerolog.Logger,
	bulker bulk.Bulk,
	agent *model.Agent,
	outputMap map[string]map[string]any,
	secretCandidateCollector OutputSecretCandidateCollector) error {
	// External OTLP output — Kibana embeds auth credentials directly in the exporter config.
	// Only mOTLP outputs carry an output_permissions block and need API key management.
	if p.Role == nil {
		zlog.Debug().Msg("no output permissions for OTLP output; skipping API key management")

		// Ensure an in-memory entry exists so retireRemovedOutputs can park records for
		// any concurrently removed outputs onto this surviving output's agent doc entry.
		if agent.Outputs == nil {
			agent.Outputs = map[string]*model.PolicyOutput{}
		}
		if _, ok := agent.Outputs[p.Name]; !ok {
			agent.Outputs[p.Name] = &model.PolicyOutput{}
		}
		if err := retireRemovedOutputs(ctx, zlog, bulker, agent, p.Name, outputMap); err != nil {
			return err
		}

		prev := agent.Outputs[p.Name]
		if prev.APIKeyID == "" && prev.APIKey == "" {
			return nil
		}
		// mOTLP → external transition: park a retirement record on this entry and clear the
		// active key fields. The entry persists so the ack/checkin gate can retire the key —
		// the same deferred pattern used by retireRemovedOutputs for surviving outputs.
		retiring := model.ToRetireAPIKeyIdsItems{
			ID:        prev.APIKeyID,
			RetiredAt: time.Now().UTC().Format(time.RFC3339),
			Output:    p.Name,
		}
		if secretID, ok := secret.ParseSecretReference(prev.APIKey); ok {
			retiring.SecretID = secretID
		}
		fields := map[string]any{
			dl.FieldPolicyOutputToRetireAPIKeyIDs: retiring,
			dl.FieldPolicyOutputAPIKeyID:          "",
			dl.FieldPolicyOutputAPIKey:            "",
			dl.FieldPolicyOutputPermissionsHash:   "",
		}
		body, err := renderUpdatePainlessScript(p.Name, fields)
		if err != nil {
			return fmt.Errorf("could not render update script for mOTLP→external transition: %w", err)
		}
		if err = bulker.Update(ctx, dl.FleetAgents, agent.Id, body, bulk.WithRefresh(), bulk.WithRetryOnConflict(3)); err != nil {
			zlog.Error().Err(err).Msg("fail to park retirement record for mOTLP→external transition")
			return fmt.Errorf("fail update agent record: %w", err)
		}
		prev.ToRetireAPIKeyIds = append(prev.ToRetireAPIKeyIds, retiring)
		prev.APIKeyID = ""
		prev.APIKey = ""
		prev.PermissionsHash = ""
		return nil
	}

	if _, ok := outputMap[p.Name]; !ok {
		zlog.Error().Err(ErrFailInjectAPIKey).Msg("unable to find output in map")
		return ErrFailInjectAPIKey
	}

	output, foundOutput := agent.Outputs[p.Name]
	if !foundOutput {
		if agent.Outputs == nil {
			agent.Outputs = map[string]*model.PolicyOutput{}
		}
		zlog.Debug().Msgf("creating agent.Outputs[%s]", p.Name)
		output = &model.PolicyOutput{}
		agent.Outputs[p.Name] = output
	}

	if err := retireRemovedOutputs(ctx, zlog, bulker, agent, p.Name, outputMap); err != nil {
		return err
	}

	_, isSecretRef := secret.ParseSecretReference(output.APIKey)
	needNewKey := false
	needUpdateKey := false
	switch {
	case output.APIKey == "":
		zlog.Debug().Msg("must generate OTLP API key as it is not present")
		needNewKey = true
	case output.Type != "" && output.Type != OutputTypeOTLP:
		zlog.Debug().Str("persistedType", output.Type).Msg("must generate OTLP API key as output type changed")
		needNewKey = true
	case !isSecretRef:
		// Managed OTLP always stores keys via fleet-secrets. A plain id:key means the entry
		// was written by a different output type under the same name (e.g., elasticsearch).
		zlog.Debug().Msg("must generate OTLP API key as existing key is not a secret reference")
		needNewKey = true
	case p.Role.Sha2 != output.PermissionsHash:
		zlog.Debug().Msg("must update OTLP API key as policy output permissions changed")
		needUpdateKey = true
	default:
		zlog.Debug().Msg("OTLP policy output permissions are the same")
	}

	if needUpdateKey {
		if err := updateOutputAPIKeyRoles(ctx, zlog, bulker, bulker, agent, p.Name, OutputTypeOTLP, output, p.Role); err != nil {
			return err
		}
	} else if needNewKey {
		zlog.Debug().
			RawJSON("fleet.policy.roles", p.Role.Raw).
			Str("fleet.policy.otlp.oldHash", output.PermissionsHash).
			Str("fleet.policy.otlp.newHash", p.Role.Sha2).
			Msg("Generating a new OTLP API key")

		ctx := zlog.WithContext(ctx)
		outputAPIKey, err := generateOutputAPIKey(ctx, bulker, agent.Id, p.Name, p.Role.Raw)
		if err != nil {
			return fmt.Errorf("failed to generate OTLP output API key: %w", err)
		}

		zlog.Info().
			Str("fleet.policy.role.hash.sha256", p.Role.Sha2).
			Str(ecs.DefaultOutputAPIKeyID, outputAPIKey.ID).
			Msg("Updating agent record to pick up OTLP output key.")

		if err := persistNewOutputAPIKey(ctx, zlog, bulker, agent, p.Name, OutputTypeOTLP, output, p.Role, outputAPIKey, secretCandidateCollector); err != nil {
			return err
		}
	}

	// Resolve the secret reference and write the raw id:secret to the output map.
	// OTLP always uses fleet-secrets storage — output.APIKey is always a $co.elastic.secret{} reference.
	// prepareOTelExporters reads this resolved value to inject the Authorization header.
	secretID, ok := secret.ParseSecretReference(output.APIKey)
	if !ok {
		return fmt.Errorf("unexpected non-reference OTLP api_key for output %q", p.Name)
	}
	resolved, err := bulker.ReadSecrets(ctx, []string{secretID})
	if err != nil {
		return fmt.Errorf("failed resolving OTLP output API key secret: %w", err)
	}
	val, ok := resolved[secretID]
	if !ok || val == "" {
		return fmt.Errorf("OTLP output API key secret %q not found", secretID)
	}
	outputMap[p.Name]["api_key"] = val
	return nil
}

func fetchAPIKeyRoles(ctx context.Context, b bulk.Bulk, apiKeyID string) (*RoleT, error) {
	res, err := b.APIKeyRead(ctx, apiKeyID, true)
	if err != nil {
		return nil, err
	}

	roleMap, err := smap.Parse(res.RoleDescriptors)
	if err != nil {
		return nil, err
	}
	r := &RoleT{
		Raw: res.RoleDescriptors,
	}

	// Stable hash on permissions payload
	if r.Sha2, err = roleMap.Hash(); err != nil {
		return nil, err
	}

	return r, nil
}

// mergeRoles takes old and new role sets and merges them following these rules:
// - take all new roles
// - append all old roles
// to avoid name collisions every old entry has a `rdstale` suffix
// if rdstale suffix already exists it uses `{index}-rdstale` to avoid further collisions
// everything ending with `rdstale` is removed on ack.
// in case we have key `123` in both old and new result will be: {"123", "123-0-rdstale"}
// in case old contains {"123", "123-0-rdstale"} and new contains {"123"} result is: {"123", "123-rdstale", "123-0-rdstale"}
func mergeRoles(zlog zerolog.Logger, old, new *RoleT) (*RoleT, error) {
	if old == nil {
		return new, nil
	}
	if new == nil {
		return old, nil
	}

	oldMap, err := smap.Parse(old.Raw)
	if err != nil {
		return nil, err
	}
	if oldMap == nil {
		return new, nil
	}

	newMap, err := smap.Parse(new.Raw)
	if err != nil {
		return nil, err
	}
	if newMap == nil {
		return old, nil
	}

	destMap := smap.Map{}
	// copy all from new
	maps.Copy(destMap, newMap)

	findNewKey := func(m smap.Map, candidate string) string {
		if before, ok := strings.CutSuffix(candidate, "-rdstale"); ok {
			candidate = before
			dashIdx := strings.LastIndex(candidate, "-")
			if dashIdx >= 0 {
				candidate = candidate[:dashIdx]
			}

		}

		// 1 should be enough, 100 is just to have some space
		for i := range 100 {
			c := fmt.Sprintf("%s-%d-rdstale", candidate, i)

			if _, exists := m[c]; !exists {
				return c
			}
		}

		return ""
	}
	// copy old
	for k, v := range oldMap {
		newKey := findNewKey(destMap, k)
		if newKey == "" {
			zlog.Warn().Msg("Failed to find a key for role assignement.")

			zlog.Debug().
				RawJSON("roles", new.Raw).
				Str("candidate", k).
				Msg("roles not included.")

			continue
		}
		destMap[newKey] = v
	}

	r := &RoleT{}
	if r.Sha2, err = destMap.Hash(); err != nil {
		return nil, err
	}
	if r.Raw, err = json.Marshal(destMap); err != nil {
		return nil, err
	}

	return r, nil
}

func renderUpdatePainlessScript(outputName string, fields map[string]any) ([]byte, error) {
	var source strings.Builder

	// prepare agent.elasticsearch_outputs[OUTPUT_NAME]
	source.WriteString(`
if (ctx._source['outputs']==null)
  {ctx._source['outputs']=new HashMap();}
if (ctx._source['outputs'][params.output_name]==null)
  {ctx._source['outputs'][params.output_name]=new HashMap();}
`)

	for field := range fields {
		if field == dl.FieldPolicyOutputToRetireAPIKeyIDs {
			// dl.FieldPolicyOutputToRetireAPIKeyIDs is a special case.
			// It's an array that gets deleted when the keys are invalidated.
			// Thus, append the old API key ID, create the field if necessary.
			fmt.Fprintf(&source, `
if (ctx._source['outputs'][params.output_name].%s==null)
  {ctx._source['outputs'][params.output_name].%s=new ArrayList();}
if (!ctx._source['outputs'][params.output_name].%s.contains(params.%s))
  {ctx._source['outputs'][params.output_name].%s.add(params.%s);}
`, field, field, field, field, field, field)
		} else {
			// Update the other fields
			fmt.Fprintf(&source, `
ctx._source['outputs'][params.output_name].%s=params.%s;`, field, field)
		}
	}
	params := make(map[string]any, len(fields)+1)
	maps.Copy(params, fields)
	params["output_name"] = outputName

	body, err := json.Marshal(map[string]any{
		"script": map[string]any{
			"lang":   "painless",
			"source": source.String(),
			"params": params,
		},
	})

	return body, err
}

func renderRemoveOutputPainlessScript(outputName string) ([]byte, error) {
	return json.Marshal(map[string]any{
		"script": map[string]any{
			"lang":   "painless",
			"source": "ctx._source['outputs'].remove(params.output_name)",
			"params": map[string]any{"output_name": outputName},
		},
	})
}

// parkRetirementRecord appends a single retirement record to the named output's
// to_retire_api_key_ids list on the agent document. The painless script uses a
// contains() check, so re-parking an identical record after a partial failure is
// safe.
func parkRetirementRecord(ctx context.Context, zlog zerolog.Logger, bulker bulk.Bulk, agentID, outputName string, record model.ToRetireAPIKeyIdsItems) error {
	fields := map[string]any{
		dl.FieldPolicyOutputToRetireAPIKeyIDs: record,
	}
	body, err := renderUpdatePainlessScript(outputName, fields)
	if err != nil {
		return fmt.Errorf("could not update painless script: %w", err)
	}
	if err = bulker.Update(ctx, dl.FleetAgents, agentID, body, bulk.WithRefresh(), bulk.WithRetryOnConflict(3)); err != nil {
		zlog.Error().Err(err).Msg("fail update agent record")
		return fmt.Errorf("fail update agent record: %w", err)
	}
	return nil
}

func generateOutputAPIKey(
	ctx context.Context,
	bulk bulk.Bulk,
	agentID,
	outputName string,
	roles []byte) (*apikey.APIKey, error) {
	name := fmt.Sprintf("%s:%s", agentID, outputName)
	zerolog.Ctx(ctx).Info().Str(ecs.AgentID, agentID).Msgf("generating output API key %s",
		name)
	return bulk.APIKeyCreate(
		ctx,
		name,
		"",
		roles,
		apikey.NewMetadata(agentID, outputName, apikey.TypeOutput),
	)
}

// agentDocOutputType normalizes the type stored in the agent doc. remote_elasticsearch is
// written as elasticsearch in the agent doc (prepareElasticsearch always passes
// OutputTypeElasticsearch), so comparisons against persisted type must normalize both sides.
// The ack and checkin gates that drive cleanup depend on this mapping.
func agentDocOutputType(t string) string {
	if t == OutputTypeRemoteElasticsearch {
		return OutputTypeElasticsearch
	}
	return t
}

// retireRemovedOutputs retires all outputs present in agent.Outputs but absent from outputMap.
// For each, it parks a retirement record on survivingOutputName and removes the stale doc entry.
//
// This is called once per surviving output, so the in-memory delete is essential: without it
// every surviving output's Prepare call would find the same stale entry and park a duplicate
// retirement record. Individual integrations can each specify a different output_id, so a single
// policy revision can remove more than one output — the full loop handles all of them.
//
// Park before remove: if the remove Update fails the record is already committed, so the key
// is still invalidated at ack and the stale entry is reprocessed next check-in. The reverse
// order would destroy the only record of the key on failure.
func retireRemovedOutputs(
	ctx context.Context,
	zlog zerolog.Logger,
	bulker bulk.Bulk,
	agent *model.Agent,
	survivingOutputName string,
	outputMap map[string]map[string]any,
) error {
	for agentOutputName, agentOutput := range agent.Outputs {
		if _, stillInPolicy := outputMap[agentOutputName]; stillInPolicy {
			continue
		}

		zlog.Info().Str(ecs.APIKeyID, agentOutput.APIKeyID).Str(ecs.PolicyOutputName, agentOutputName).Msg("Output removed, will retire API key")

		// Transfer any pending retirement records from the removed entry to the survivor
		// before deleting the entry. Without this, records parked by a prior key rotation
		// or mOTLP→external transition would be lost.
		for _, pending := range agentOutput.ToRetireAPIKeyIds {
			if err := parkRetirementRecord(ctx, zlog, bulker, agent.Id, survivingOutputName, pending); err != nil {
				return err
			}
		}

		// Park the active key on the survivor. Skip when APIKeyID is empty to avoid writing
		// a junk record with an empty ID that invalidateAPIKeys would silently discard.
		// Also skip if a record for this key ID is already on the survivor exists and prior painless script failed.
		survivor := agent.Outputs[survivingOutputName]
		alreadyParked := survivor != nil && slices.ContainsFunc(survivor.ToRetireAPIKeyIds, func(r model.ToRetireAPIKeyIdsItems) bool {
			return r.ID == agentOutput.APIKeyID
		})
		if agentOutput.APIKeyID != "" && !alreadyParked {
			retiring := model.ToRetireAPIKeyIdsItems{
				ID:        agentOutput.APIKeyID,
				RetiredAt: time.Now().UTC().Format(time.RFC3339),
				Output:    agentOutputName,
			}
			if secretID, ok := secret.ParseSecretReference(agentOutput.APIKey); ok {
				retiring.SecretID = secretID
			}
			if err := parkRetirementRecord(ctx, zlog, bulker, agent.Id, survivingOutputName, retiring); err != nil {
				return err
			}
		}

		body, err := renderRemoveOutputPainlessScript(agentOutputName)
		if err != nil {
			return fmt.Errorf("could not create request body to update agent: %w", err)
		}
		if err = bulker.Update(ctx, dl.FleetAgents, agent.Id, body, bulk.WithRefresh(), bulk.WithRetryOnConflict(3)); err != nil {
			zlog.Error().Err(err).Msg("fail update agent record")
			return fmt.Errorf("fail update agent record: %w", err)
		}
		// Remove from the in-memory map so that the next surviving output's retireRemovedOutputs
		// call does not re-park the same entry. Safe to delete during range per Go spec.
		delete(agent.Outputs, agentOutputName)
	}
	return nil
}

// updateOutputAPIKeyRoles merges new role permissions onto an existing API key and persists
// the updated hash and type to the agent doc. outputBulker is used for the API key read/update
// operations (differs from bulker for remote-elasticsearch outputs); bulker is always used
// for the agent-doc update.
func updateOutputAPIKeyRoles(
	ctx context.Context,
	zlog zerolog.Logger,
	bulker bulk.Bulk,
	outputBulker bulk.Bulk,
	agent *model.Agent,
	outputName string,
	agentDocType string,
	output *model.PolicyOutput,
	role *RoleT,
) error {
	zlog.Debug().
		RawJSON("roles", role.Raw).
		Str("oldHash", output.PermissionsHash).
		Str("newHash", role.Sha2).
		Msg("Generating a new API key")

	// query current api key for roles so we don't lose permissions in the meantime
	currentRoles, err := fetchAPIKeyRoles(ctx, outputBulker, output.APIKeyID)
	if err != nil {
		zlog.Error().
			Str("apiKeyID", output.APIKeyID).
			Err(err).Msg("fail fetching roles for key")
		return err
	}

	// merge roles with role
	newRoles, err := mergeRoles(zlog, currentRoles, role)
	if err != nil {
		zlog.Error().
			Str("apiKeyID", output.APIKeyID).
			Err(err).Msg("fail merging roles for key")
		return err
	}

	// hash provided is only for merging request together and not persisted
	err = outputBulker.APIKeyUpdate(ctx, output.APIKeyID, newRoles.Sha2, newRoles.Raw)
	if err != nil {
		zlog.Error().Err(err).Msg("fail generate output key")
		zlog.Debug().RawJSON("roles", newRoles.Raw).Str("sha", newRoles.Sha2).Err(err).Msg("roles not updated")
		return err
	}

	output.Type = agentDocType
	output.PermissionsHash = role.Sha2
	zlog.Debug().
		Str("hash.sha256", role.Sha2).
		Str("roles", string(role.Raw)).
		Msg("Updating agent record to pick up most recent roles.")

	fields := map[string]any{
		dl.FieldPolicyOutputPermissionsHash: role.Sha2,
		dl.FiledType:                        agentDocType,
	}

	// Using painless script to update permission hash for updated key
	body, err := renderUpdatePainlessScript(outputName, fields)
	if err != nil {
		return err
	}

	if err = bulker.Update(ctx, dl.FleetAgents, agent.Id, body, bulk.WithRefresh(), bulk.WithRetryOnConflict(3)); err != nil {
		zlog.Error().Err(err).Msg("fail update agent record")
		return err
	}
	return nil
}

// persistNewOutputAPIKey writes a new API key secret to .fleet-secrets, updates the agent
// doc with the new key reference (and a retirement record for the previous key if one exists),
// and syncs the in-memory output. agentDocType is part of key state: it determines ack-time
// routing and whether a type transition requires rotation, so it is written unconditionally
// alongside every new key.
func persistNewOutputAPIKey(
	ctx context.Context,
	zlog zerolog.Logger,
	bulker bulk.Bulk,
	agent *model.Agent,
	outputName string,
	agentDocType string,
	output *model.PolicyOutput,
	role *RoleT,
	outputAPIKey *apikey.APIKey,
	secretCandidateCollector OutputSecretCandidateCollector,
) error {
	secretID, err := bulker.WriteSecret(ctx, outputAPIKey.Agent())
	if err != nil {
		return fmt.Errorf("failed writing output API key secret: %w", err)
	}
	apiKeyRef := secret.MakeSecretReference(secretID)

	fields := map[string]any{
		dl.FieldPolicyOutputAPIKey:          apiKeyRef,
		dl.FieldPolicyOutputAPIKeyID:        outputAPIKey.ID,
		dl.FieldPolicyOutputPermissionsHash: role.Sha2,
		dl.FiledType:                        agentDocType,
	}
	if output.APIKeyID != "" {
		retiring := model.ToRetireAPIKeyIdsItems{
			ID:        output.APIKeyID,
			RetiredAt: time.Now().UTC().Format(time.RFC3339),
			Output:    outputName,
		}
		if secretID, ok := secret.ParseSecretReference(output.APIKey); ok {
			retiring.SecretID = secretID
		}
		fields[dl.FieldPolicyOutputToRetireAPIKeyIDs] = retiring
	}

	// Using painless script to append the old keys to the history
	body, err := renderUpdatePainlessScript(outputName, fields)
	if err != nil {
		return fmt.Errorf("could not update painless script: %w", err)
	}

	if err = bulker.Update(ctx, dl.FleetAgents, agent.Id, body, bulk.WithRefresh(), bulk.WithRetryOnConflict(3)); err != nil {
		zlog.Error().Err(err).Msg("fail update agent record")
		// The update may have been committed by Elasticsearch even when the client
		// returns an error, for example when the request context expires while
		// waiting for the response. Deleting the secret here can therefore leave
		// the agent document pointing at a missing secret.
		if secretCandidateCollector != nil {
			candidate := OutputSecretCandidate{
				AgentID:    agent.Id,
				OutputName: outputName,
				SecretID:   secretID,
				SecretRef:  apiKeyRef,
			}
			if !secretCandidateCollector.Add(candidate) {
				zlog.Warn().Str("secret.id", secretID).Msg("failed to enqueue output secret reconciliation candidate")
			}
		}
		return fmt.Errorf("fail update agent record: %w", err)
	}

	// Now that all is done, we can update the output on the agent variable
	// Right not it's more for consistency and to ensure the in-memory agent
	// data is correct and in sync with ES, so it can be safely used after
	// this method returns.
	output.Type = agentDocType
	output.APIKey = apiKeyRef
	output.APIKeyID = outputAPIKey.ID
	output.PermissionsHash = role.Sha2 // for the sake of consistency
	return nil
}
