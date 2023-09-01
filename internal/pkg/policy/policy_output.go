// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"go.elastic.co/apm/v2"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/smap"
)

const (
	OutputTypeElasticsearch = "elasticsearch"
	OutputTypeLogstash      = "logstash"
	OutputTypeKafka         = "kafka"
)

var (
	ErrNoOutputPerms    = errors.New("output permission sections not found")
	ErrFailInjectAPIKey = errors.New("fail inject api key")
)

type Output struct {
	Name string
	Type string
	Role *RoleT
}

// Prepare prepares the output p to be sent to the elastic-agent
// The agent might be mutated for an elasticsearch output
func (p *Output) Prepare(ctx context.Context, zlog zerolog.Logger, bulker bulk.Bulk, agent *model.Agent, outputMap smap.Map) error {
	span, ctx := apm.StartSpan(ctx, "prepareOutput", "process")
	defer span.End()
	span.Context.SetLabel("output_type", p.Type)
	zlog = zlog.With().
		Str("fleet.agent.id", agent.Id).
		Str("fleet.policy.output.name", p.Name).Logger()

	switch p.Type {
	case OutputTypeElasticsearch:
		zlog.Debug().Msg("preparing elasticsearch output")
		if err := p.prepareElasticsearch(ctx, zlog, bulker, agent, outputMap); err != nil {
			return fmt.Errorf("failed to prepare elasticsearch output %q: %w", p.Name, err)
		}
	case OutputTypeLogstash:
		zlog.Debug().Msg("preparing logstash output")
		zlog.Info().Msg("no actions required for logstash output preparation")
	case OutputTypeKafka:
		zlog.Debug().Msg("preparing kafka output")
		zlog.Info().Msg("no actions required for kafka output preparation")
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
	agent *model.Agent,
	outputMap smap.Map) error {
	// The role is required to do api key management
	if p.Role == nil {
		zlog.Error().
			Msg("policy does not contain required output permission section")
		return ErrNoOutputPerms
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
	case p.Role.Sha2 != output.PermissionsHash:
		// the is actually the OutputPermissionsHash for the default hash. The Agent
		// document on ES does not have OutputPermissionsHash for any other output
		// besides the default one. It seems to me error-prone to rely on the default
		// output permissions hash to generate new API keys for other outputs.
		zlog.Debug().Msg("must generate api key as policy output permissions changed")
		needUpdateKey = true
	default:
		zlog.Debug().Msg("policy output permissions are the same")
	}

	if needUpdateKey {
		zlog.Debug().
			RawJSON("roles", p.Role.Raw).
			Str("oldHash", output.PermissionsHash).
			Str("newHash", p.Role.Sha2).
			Msg("Generating a new API key")

		// query current api key for roles so we don't lose permissions in the meantime
		currentRoles, err := fetchAPIKeyRoles(ctx, bulker, output.APIKeyID)
		if err != nil {
			zlog.Error().
				Str("apiKeyID", output.APIKeyID).
				Err(err).Msg("fail fetching roles for key")
			return err
		}

		// merge roles with p.Role
		newRoles, err := mergeRoles(zlog, currentRoles, p.Role)
		if err != nil {
			zlog.Error().
				Str("apiKeyID", output.APIKeyID).
				Err(err).Msg("fail merging roles for key")
			return err
		}

		// hash provided is only for merging request together and not persisted
		err = bulker.APIKeyUpdate(ctx, output.APIKeyID, newRoles.Sha2, newRoles.Raw)
		if err != nil {
			zlog.Error().Err(err).Msg("fail generate output key")
			zlog.Debug().RawJSON("roles", newRoles.Raw).Str("sha", newRoles.Sha2).Err(err).Msg("roles not updated")
			return err
		}

		output.PermissionsHash = p.Role.Sha2 // for the sake of consistency
		zlog.Debug().
			Str("hash.sha256", p.Role.Sha2).
			Str("roles", string(p.Role.Raw)).
			Msg("Updating agent record to pick up most recent roles.")

		fields := map[string]interface{}{
			dl.FieldPolicyOutputPermissionsHash: p.Role.Sha2,
		}

		// Using painless script to update permission hash for updated key
		body, err := renderUpdatePainlessScript(p.Name, fields)
		if err != nil {
			return err
		}

		if err = bulker.Update(ctx, dl.FleetAgents, agent.Id, body, bulk.WithRefresh(), bulk.WithRetryOnConflict(3)); err != nil {
			zlog.Error().Err(err).Msg("fail update agent record")
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
			generateOutputAPIKey(ctx, bulker, agent.Id, p.Name, p.Role.Raw)
		if err != nil {
			return fmt.Errorf("failed generate output API key: %w", err)
		}

		// When a new keys is generated we need to update the Agent record,
		// this will need to be updated when multiples remote Elasticsearch output
		// are supported.
		zlog.Info().
			Str("fleet.policy.role.hash.sha256", p.Role.Sha2).
			Str(logger.DefaultOutputAPIKeyID, outputAPIKey.ID).
			Msg("Updating agent record to pick up default output key.")

		fields := map[string]interface{}{
			dl.FieldPolicyOutputAPIKey:          outputAPIKey.Agent(),
			dl.FieldPolicyOutputAPIKeyID:        outputAPIKey.ID,
			dl.FieldPolicyOutputPermissionsHash: p.Role.Sha2,
		}

		if !foundOutput {
			fields[dl.FiledType] = OutputTypeElasticsearch
		}
		if output.APIKeyID != "" {
			fields[dl.FieldPolicyOutputToRetireAPIKeyIDs] = model.ToRetireAPIKeyIdsItems{
				ID:        output.APIKeyID,
				RetiredAt: time.Now().UTC().Format(time.RFC3339),
			}
		}

		// Using painless script to append the old keys to the history
		body, err := renderUpdatePainlessScript(p.Name, fields)
		if err != nil {
			return fmt.Errorf("could no tupdate painless script: %w", err)
		}

		if err = bulker.Update(ctx, dl.FleetAgents, agent.Id, body, bulk.WithRefresh(), bulk.WithRetryOnConflict(3)); err != nil {
			zlog.Error().Err(err).Msg("fail update agent record")
			return fmt.Errorf("fail update agent record: %w", err)
		}

		// Now that all is done, we can update the output on the agent variable
		// Right not it's more for consistency and to ensure the in-memory agent
		// data is correct and in sync with ES, so it can be safely used after
		// this method returns.
		output.Type = OutputTypeElasticsearch
		output.APIKey = outputAPIKey.Agent()
		output.APIKeyID = outputAPIKey.ID
		output.PermissionsHash = p.Role.Sha2 // for the sake of consistency
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
	if err := setMapObj(outputMap, output.APIKey, p.Name, "api_key"); err != nil {
		return err
	}

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
	for k, v := range newMap {
		destMap[k] = v
	}

	findNewKey := func(m smap.Map, candidate string) string {
		if strings.HasSuffix(candidate, "-rdstale") {
			candidate = strings.TrimSuffix(candidate, "-rdstale")
			dashIdx := strings.LastIndex(candidate, "-")
			if dashIdx >= 0 {
				candidate = candidate[:dashIdx]
			}

		}

		// 1 should be enough, 100 is just to have some space
		for i := 0; i < 100; i++ {
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

func renderUpdatePainlessScript(outputName string, fields map[string]interface{}) ([]byte, error) {
	var source strings.Builder

	// prepare agent.elasticsearch_outputs[OUTPUT_NAME]
	source.WriteString(fmt.Sprintf(`
if (ctx._source['outputs']==null)
  {ctx._source['outputs']=new HashMap();}
if (ctx._source['outputs']['%s']==null)
  {ctx._source['outputs']['%s']=new HashMap();}
`, outputName, outputName))

	for field := range fields {
		if field == dl.FieldPolicyOutputToRetireAPIKeyIDs {
			// dl.FieldPolicyOutputToRetireAPIKeyIDs is a special case.
			// It's an array that gets deleted when the keys are invalidated.
			// Thus, append the old API key ID, create the field if necessary.
			source.WriteString(fmt.Sprintf(`
if (ctx._source['outputs']['%s'].%s==null)
  {ctx._source['outputs']['%s'].%s=new ArrayList();}
ctx._source['outputs']['%s'].%s.add(params.%s);
`, outputName, field, outputName, field, outputName, field, field))
		} else {
			// Update the other fields
			source.WriteString(fmt.Sprintf(`
ctx._source['outputs']['%s'].%s=params.%s;`,
				outputName, field, field))
		}
	}

	body, err := json.Marshal(map[string]interface{}{
		"script": map[string]interface{}{
			"lang":   "painless",
			"source": source.String(),
			"params": fields,
		},
	})

	return body, err
}

func generateOutputAPIKey(
	ctx context.Context,
	bulk bulk.Bulk,
	agentID,
	outputName string,
	roles []byte) (*apikey.APIKey, error) {
	name := fmt.Sprintf("%s:%s", agentID, outputName)
	zerolog.Ctx(ctx).Info().Msgf("generating output API key %s for agent ID %s",
		name, agentID)
	return bulk.APIKeyCreate(
		ctx,
		name,
		"",
		roles,
		apikey.NewMetadata(agentID, outputName, apikey.TypeOutput),
	)
}

func setMapObj(obj map[string]interface{}, val interface{}, keys ...string) error {
	if len(keys) == 0 {
		return fmt.Errorf("no key to be updated: %w", ErrFailInjectAPIKey)
	}

	for _, k := range keys[:len(keys)-1] {
		v, ok := obj[k]
		if !ok {
			return fmt.Errorf("no key %q not present on MapObj: %w",
				k, ErrFailInjectAPIKey)
		}

		obj, ok = v.(map[string]interface{})
		if !ok {
			return fmt.Errorf("cannot cast %T to map[string]interface{}: %w",
				obj, ErrFailInjectAPIKey)
		}
	}

	k := keys[len(keys)-1]
	obj[k] = val

	return nil
}
