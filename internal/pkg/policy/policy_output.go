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
	switch p.Type {
	case OutputTypeElasticsearch:
		if err := p.prepareElasticsearch(ctx, zlog, bulker, agent, outputMap); err != nil {
			return fmt.Errorf("failed to prepare elasticsearch output %q: %w", p.Name, err)
		}
	case OutputTypeLogstash:
		zlog.Debug().Msg("preparing logstash output")
		zlog.Info().Msg("no actions required for logstash output preparation")
	default:
		zlog.Error().Msgf("unknown output type: %s; skipping preparation", p.Type)
		return fmt.Errorf("encountered unexpected output type while preparing outputs: %s", p.Type)
	}
	return nil
}

func (p *Output) prepareElasticsearch(ctx context.Context, zlog zerolog.Logger, bulker bulk.Bulk, agent *model.Agent, outputMap smap.Map) error {
	zlog = zlog.With().
		Str("fleet.agent.id", agent.Id).
		Str("fleet.policy.output.name", p.Name).Logger()

	zlog.Info().Msg("preparing elasticsearch output")

	// The role is required to do api key management
	if p.Role == nil {
		zlog.Error().
			Str("fleet.output.name", p.Name).
			Msg("policy does not contain required output permission section")
		return ErrNoOutputPerms
	}

	// 1 - just use the new ElasticsearchOutputs
	// 2 - make the tests check if they're correctly filled in
	// 3 - ensure Default* is made empty/nil at the end

	// Determine whether we need to generate an output ApiKey.
	// This is accomplished by comparing the sha2 hash stored in the agent
	// record with the precalculated sha2 hash of the role.

	// Note: This will need to be updated when doing multi-cluster elasticsearch support
	// Currently, we only have access to the token for the elasticsearch instance fleet-server
	// is monitors. When updating for multiple ES instances we need to tie the token to the output.
	needNewKey := true
	switch {
	case agent.DefaultAPIKey == "":
		zlog.Debug().Msg("must generate api key as default API key is not present")
	case p.Role.Sha2 != agent.PolicyOutputPermissionsHash:
		// the is actually the OutputPermissionsHash for the default hash. The Agent
		// document on ES does not have OutputPermissionsHash for any other output
		// besides the default one. It seems to me error-prone to rely on the default
		// output permissions hash to generate new API keys for other outputs.
		zlog.Debug().Msg("must generate api key as policy output permissions changed")
	default:
		needNewKey = false
		zlog.Debug().Msg("policy output permissions are the same")
	}

	if needNewKey {
		zlog.Debug().
			RawJSON("fleet.policy.roles", p.Role.Raw).
			Str("fleet.policy.default.oldHash", agent.PolicyOutputPermissionsHash).
			Str("fleet.policy.default.newHash", p.Role.Sha2).
			Msg("Generating a new API key")

		ctx := zlog.WithContext(ctx)
		outputAPIKey, err := generateOutputAPIKey(ctx, bulker, agent.Id, p.Name, p.Role.Raw)
		if err != nil {
			zlog.Error().Err(err).Msg("fail generate output key")
			return err
		}

		agent.DefaultAPIKey = outputAPIKey.Agent()

		// When a new keys is generated we need to update the Agent record,
		// this will need to be updated when multiples Elasticsearch output
		// are used.
		zlog.Info().
			Str("fleet.role.hash.sha256", p.Role.Sha2).
			Str(logger.DefaultOutputAPIKeyID, outputAPIKey.ID).
			Msg("Updating agent record to pick up default output key.")

		fields := map[string]interface{}{
			dl.FieldDefaultAPIKey:               outputAPIKey.Agent(),
			dl.FieldDefaultAPIKeyID:             outputAPIKey.ID,
			dl.FieldPolicyOutputPermissionsHash: p.Role.Sha2,
		}
		if agent.DefaultAPIKeyID != "" {
			fields[dl.FieldDefaultAPIKeyHistory] = model.DefaultAPIKeyHistoryItems{
				ID:        agent.DefaultAPIKeyID,
				RetiredAt: time.Now().UTC().Format(time.RFC3339),
			}
		}

		// Using painless script to append the old keys to the history
		body, err := renderUpdatePainlessScript(fields)
		if err != nil {
			return fmt.Errorf("could no tupdate painless script: %w", err)
		}

		if err = bulker.Update(ctx, dl.FleetAgents, agent.Id, body); err != nil {
			zlog.Error().Err(err).Msg("fail update agent record")
			return fmt.Errorf("fail update agent record: %w", err)
		}
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
	//
	// WIP:
	// The agent struct is a pointer, thus shared between the runs of Prepare
	// for each output. Given 2 outputs (1 and 2), if 1 gets a new API key,
	// agent.DefaultAPIKey changes. However, if 2 does not get one, the code
	// below runs anyway, therefore the API key for output 2 will be set to the
	// api key for output 1
	// The agent struct cannot be shared! The new API key must be its own local
	// variable and a special case for the 'default output' has to handle
	// updating agent.DefaultAPIKey.
	if err := setMapObj(outputMap, agent.DefaultAPIKey, p.Name, "api_key"); err != nil {
		return err
	}

	return nil
}

func renderUpdatePainlessScript(fields map[string]interface{}) ([]byte, error) {
	var source strings.Builder
	for field := range fields {
		if field == dl.FieldDefaultAPIKeyHistory {
			source.WriteString(fmt.Sprint("if (ctx._source.", field, "==null) {ctx._source.", field, "=new ArrayList();} ctx._source.", field, ".add(params.", field, ");"))
		} else {
			source.WriteString(fmt.Sprint("ctx._source.", field, "=", "params.", field, ";"))
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

func generateOutputAPIKey(ctx context.Context, bulk bulk.Bulk, agentID, outputName string, roles []byte) (*apikey.APIKey, error) {
	name := fmt.Sprintf("%s:%s", agentID, outputName)
	zerolog.Ctx(ctx).Info().Msgf("generating output API key %s for agent ID %s",
		name, agentID)
	return bulk.APIKeyCreate(
		ctx,
		name,
		"",
		roles,
		apikey.NewMetadata(agentID, apikey.TypeOutput),
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
