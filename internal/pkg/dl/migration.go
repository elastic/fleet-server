// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/elastic/go-elasticsearch/v7/esapi"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dsl"
)

type (
	migrationFn       func(context.Context, bulk.Bulk) error
	migrationBodyFn   func() (string, string, []byte, error)
	migrationResponse struct {
		Took             int  `json:"took"`
		TimedOut         bool `json:"timed_out"`
		Total            int  `json:"total"`
		Updated          int  `json:"updated"`
		Deleted          int  `json:"deleted"`
		Batches          int  `json:"batches"`
		VersionConflicts int  `json:"version_conflicts"`
		Noops            int  `json:"noops"`
		Retries          struct {
			Bulk   int `json:"bulk"`
			Search int `json:"search"`
		} `json:"retries"`
		Failures []json.RawMessage `json:"failures"`
	}
)

// timeNow is used to get the current time. It should be replaced for testing.
var timeNow = time.Now

// Migrate applies, in sequence, the migration functions. Currently, each migration
// function is responsible to ensure it only applies the migration if needed,
// being a no-op otherwise.
func Migrate(ctx context.Context, bulker bulk.Bulk) error {
	for _, fn := range []migrationFn{migrateTov7_15, migrateToV8_5} {
		if err := fn(ctx, bulker); err != nil {
			return err
		}
	}

	return nil
}

func migrate(ctx context.Context, bulker bulk.Bulk, fn migrationBodyFn) (int, error) {
	var updatedDocs int
	for {
		name, index, body, err := fn()
		if err != nil {
			return updatedDocs,
				fmt.Errorf("failed to prepare request for migration %s: %w",
					name, err)
		}

		resp, err := applyMigration(ctx, name, index, bulker, body)
		if err != nil {
			log.Err(err).
				Bytes("http.request.body.content", body).
				Msgf("migration %s failed", name)
			return updatedDocs, fmt.Errorf("failed to apply migration %q: %w",
				name, err)
		}
		updatedDocs += resp.Updated
		if resp.VersionConflicts == 0 {
			break
		}
	}

	return updatedDocs, nil
}

func applyMigration(ctx context.Context, name string, index string, bulker bulk.Bulk, body []byte) (migrationResponse, error) {
	start := time.Now()

	client := bulker.Client()

	reader := bytes.NewReader(body)

	opts := []func(*esapi.UpdateByQueryRequest){
		client.UpdateByQuery.WithBody(reader),
		client.UpdateByQuery.WithContext(ctx),
		client.UpdateByQuery.WithRefresh(true),
		client.UpdateByQuery.WithConflicts("proceed"),
	}

	res, err := client.UpdateByQuery([]string{index}, opts...)
	if err != nil {
		return migrationResponse{}, err
	}

	if res.IsError() {
		if res.StatusCode == http.StatusNotFound {
			// Ignore index not created yet; nothing to upgrade
			return migrationResponse{}, nil
		}

		return migrationResponse{}, fmt.Errorf("migrate %s UpdateByQuery failed: %s",
			name, res.String())
	}

	resp := migrationResponse{}

	decoder := json.NewDecoder(res.Body)
	if err := decoder.Decode(&resp); err != nil {
		return migrationResponse{}, errors.Wrap(err, "decode UpdateByQuery response")
	}

	log.Info().
		Str("fleet.migration.name", name).
		Int("fleet.migration.es.took", resp.Took).
		Bool("fleet.migration.es.timed_out", resp.TimedOut).
		Int("fleet.migration.total", resp.Total).
		Int("fleet.migration.updated", resp.Updated).
		Int("fleet.migration.deleted", resp.Deleted).
		Int("fleet.migration.batches", resp.Batches).
		Int("fleet.migration.version_conflicts", resp.VersionConflicts).
		Int("fleet.migration.noops", resp.Noops).
		Int("fleet.migration.retries.bulk", resp.Retries.Bulk).
		Int("fleet.migration.retries.search", resp.Retries.Search).
		Dur("fleet.migration.total.duration", time.Since(start)).
		Msgf("migration %s done", name)

	for _, fail := range resp.Failures {
		log.Error().RawJSON("failure", fail).Msgf("failed applying %s migration", name)
	}

	return resp, err
}

// ============================== V7.15 migration ==============================
func migrateTov7_15(ctx context.Context, bulker bulk.Bulk) error {
	log.Debug().Msg("applying migration to v7.15")
	_, err := migrate(ctx, bulker, migrateAgentMetadata)
	if err != nil {
		return fmt.Errorf("v7.15.0 data migration failed: %w", err)
	}

	return nil
}

// FleetServer 7.15 added a new *AgentMetadata field to the Agent record.
// This field was populated in new enrollments in 7.15 and later; however, the
// change was not backported to support 7.14. The security team is reliant on the
// existence of this field in 7.16, so the following migration was added to
// support upgrade from 7.14.
//
// It is currently safe to run this in the background; albeit with some
// concern on conflicts. The conflict risk exists regardless as N Fleet Servers
// can be run in parallel at the same time.
//
// As the update only occurs once, the 99.9% case is a noop.
func migrateAgentMetadata() (string, string, []byte, error) {
	const migrationName = "AgentMetadata"
	query := dsl.NewRoot()
	query.Query().Bool().MustNot().Exists("agent.id")

	painless := "ctx._source.agent = [:]; ctx._source.agent.id = ctx._id;"
	query.Param("script", painless)

	body, err := query.MarshalJSON()
	if err != nil {
		return migrationName, FleetAgents, nil, fmt.Errorf("could not marshal ES query: %w", err)
	}

	return migrationName, FleetAgents, body, nil
}

// ============================== V8.5.0 migration =============================
// https://github.com/elastic/fleet-server/issues/1672

func migrateToV8_5(ctx context.Context, bulker bulk.Bulk) error {
	log.Debug().Msg("applying migration to v8.5.0")
	migrated, err := migrate(ctx, bulker, migrateAgentOutputs)
	if err != nil {
		return fmt.Errorf("v8.5.0 data migration failed: %w", err)
	}

	// The migration was necessary and indeed run, thus we need to regenerate
	// the API keys for all agents. In order to do so, we increase the policy
	// coordinator index to force a policy update.
	if migrated > 0 {
		_, err := migrate(ctx, bulker, migratePolicyCoordinatorIdx)
		if err != nil {
			return fmt.Errorf("v8.5.0 data migration failed: %w", err)
		}
	}

	return nil
}

// migrateAgentOutputs performs the necessary changes on the Agent documents
// to introduce the `Outputs` field.
//
// FleetServer 8.5.0 introduces a new field to the Agent document, Outputs, to
// store the outputs credentials and data. The DefaultAPIKey, DefaultAPIKeyID,
// DefaultAPIKeyHistory and PolicyOutputPermissionsHash are now deprecated in
// favour of the new `Outputs` fields, which maps the output name to its data.
// This change fixes https://github.com/elastic/fleet-server/issues/1672.
//
// The change is backward compatible as the deprecated fields are just set to
// their zero value and an older version of FleetServer can repopulate them.
// However, reverting FleetServer to an older version might cause very issue
// this change fixes.
func migrateAgentOutputs() (string, string, []byte, error) {
	const (
		migrationName        = "AgentOutputs"
		fieldOutputs         = "outputs"
		fieldDefaultAPIKeyID = "default_api_key_id" // nolint:gosec,G101 // this is not a credential
		fieldRetiredAt       = "retiredAt"
	)

	root := dsl.NewRoot()
	tmpl := dsl.NewTmpl()

	root.Query().Bool().Must().Term(fieldDefaultAPIKeyID, tmpl.Bind(fieldDefaultAPIKeyID), nil)

	fields := map[string]interface{}{fieldRetiredAt: timeNow().UTC().Format(time.RFC3339)}
	painless := `
// set up the new fields
ctx._source['` + fieldOutputs + `']=new HashMap();
ctx._source['` + fieldOutputs + `']['default']=new HashMap();
ctx._source['` + fieldOutputs + `']['default'].to_retire_api_key_ids=new ArrayList();

// copy 'default_api_key_history' to new 'outputs' field
ctx._source['` + fieldOutputs + `']['default'].type="elasticsearch";
if (ctx._source.default_api_key_history != null && ctx._source.default_api_key_history.length > 0) {
    ctx._source['` + fieldOutputs + `']['default'].to_retire_api_key_ids=ctx._source.default_api_key_history;
}

Map map = new HashMap();
map.put("retired_at", params.` + fieldRetiredAt + `);
map.put("id", ctx._source.default_api_key_id);

// Make current API key empty, so fleet-server will generate a new one
// Add current API jey to be retired
if (ctx._source['` + fieldOutputs + `']['default'].to_retire_api_key_ids != null) {
	ctx._source['` + fieldOutputs + `']['default'].to_retire_api_key_ids.add(map);
}
ctx._source['` + fieldOutputs + `']['default'].api_key="";
ctx._source['` + fieldOutputs + `']['default'].api_key_id="";
ctx._source['` + fieldOutputs + `']['default'].permissions_hash=ctx._source.policy_output_permissions_hash;

// Erase deprecated fields
ctx._source.default_api_key_history=null;
ctx._source.default_api_key="";
ctx._source.default_api_key_id="";
ctx._source.policy_output_permissions_hash="";
`
	root.Param("script", map[string]interface{}{
		"lang":   "painless",
		"source": painless,
		"params": fields,
	})

	tmpl.MustResolve(root)

	body, err := tmpl.Render(map[string]interface{}{fieldDefaultAPIKeyID: ""})
	if err != nil {
		return migrationName, FleetAgents, nil, fmt.Errorf("could not marshal ES query: %w", err)
	}

	return migrationName, FleetAgents, body, nil
}

// migratePolicyCoordinatorIdx increases the policy's CoordinatorIdx to force
// a policy update ensuring the output data will be migrated to the new
// Agent.Outputs field. See migrateAgentOutputs and https://github.com/elastic/fleet-server/issues/1672
// for details.
func migratePolicyCoordinatorIdx() (string, string, []byte, error) {
	const migrationName = "PolicyCoordinatorIdx"

	query := dsl.NewRoot()
	query.Query().MatchAll()
	painless := `ctx._source.coordinator_idx++;`
	query.Param("script", painless)

	body, err := query.MarshalJSON()
	if err != nil {
		log.Debug().Str("painlessScript", painless).
			Msgf("%s: failed painless script", migrationName)
		return migrationName, FleetPolicies, nil, fmt.Errorf("could not marshal ES query: %w", err)
	}

	return migrationName, FleetPolicies, body, nil
}
