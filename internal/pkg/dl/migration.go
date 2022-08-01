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

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dsl"

	"github.com/elastic/go-elasticsearch/v7/esapi"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

type (
	migrationBodyFn   func() (string, []byte, error)
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

func Migrate(ctx context.Context, bulker bulk.Bulk) error {
	for _, fn := range []migrationBodyFn{migrateAgentMetadata, migrateElasticsearchOutputs} {
		if _, err := migrate(ctx, bulker, fn); err != nil {
			return err
		}
	}

	return nil
}

func applyMigration(ctx context.Context, name string, bulker bulk.Bulk, body []byte) (migrationResponse, error) {
	start := time.Now()

	client := bulker.Client()

	reader := bytes.NewReader(body)

	opts := []func(*esapi.UpdateByQueryRequest){
		client.UpdateByQuery.WithBody(reader),
		client.UpdateByQuery.WithContext(ctx),
		client.UpdateByQuery.WithRefresh(true),
		client.UpdateByQuery.WithConflicts("proceed"),
	}

	res, err := client.UpdateByQuery([]string{FleetAgents}, opts...)
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

func migrate(ctx context.Context, bulker bulk.Bulk, fn migrationBodyFn) (int, error) {
	var updatedDocs int
	for {
		name, body, err := fn()
		if err != nil {
			return updatedDocs, fmt.Errorf(": %w", err)
		}

		resp, err := applyMigration(ctx, name, bulker, body)
		if err != nil {
			return updatedDocs, fmt.Errorf("failed to apply migration %q: %w",
				name, err)
		}
		updatedDocs += resp.Updated
		if resp.VersionConflicts == 0 {
			break
		}

		time.Sleep(time.Second)
	}
	return updatedDocs, nil
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
func migrateAgentMetadata() (string, []byte, error) {
	const migrationName = "AgentMetadata"
	root := dsl.NewRoot()
	root.Query().Bool().MustNot().Exists("agent.id")

	painless := "ctx._source.agent = [:]; ctx._source.agent.id = ctx._id;"
	root.Param("script", painless)

	body, err := root.MarshalJSON()
	if err != nil {
		return migrationName, nil, fmt.Errorf("could not marshal ES query: %w", err)
	}

	return migrationName, body, nil
}

// FleetServer 8.4.0 introduces a new field to the Agent document, Outputs, to
// store the outputs credentials and data. The DefaultAPIKey, DefaultAPIKeyID,
// DefaultAPIKeyHistory and PolicyOutputPermissionsHash are now deprecated in
// favour of the new `Outputs` fields, which maps the output name to its data.
// This change fixes https://github.com/elastic/fleet-server/issues/1672.

// The change is backward compatible as the deprecated fields are just set to
// their zero value and an older version of FleetServer can repopulate them.
// However, reverting FleetServer to an older version might cause very issue
// this change fixes.
func migrateElasticsearchOutputs() (string, []byte, error) {
	const migrationName = "ElasticsearchOutputs"

	root := dsl.NewRoot()
	root.Query().Bool().MustNot().Exists("elasticsearch_outputs")

	painless := `
// set up the new filed
if (ctx._source['elasticsearch_outputs']==null)
 {ctx._source['elasticsearch_outputs']=new HashMap();}
if (ctx._source['elasticsearch_outputs']['default']==null)
 {ctx._source['elasticsearch_outputs']['default']=new HashMap();}

// copy old values to new 'elasticsearch_outputs' field
ctx._source['elasticsearch_outputs']['default'].to_retire_api_keys=ctx._source.default_api_key_history;
ctx._source['elasticsearch_outputs']['default'].api_key=ctx._source.default_api_key;
ctx._source['elasticsearch_outputs']['default'].api_key_id=ctx._source.default_api_key_id;
ctx._source['elasticsearch_outputs']['default'].policy_permissions_hash=ctx._source.policy_output_permissions_hash;

// Erase deprecated fields
ctx._source.default_api_key_history=null;
ctx._source.default_api_key="";
ctx._source.default_api_key_id="";
ctx._source.policy_output_permissions_hash="";
`
	root.Param("script", painless)

	body, err := root.MarshalJSON()
	if err != nil {
		return migrationName, nil, fmt.Errorf("could not marshal ES query: %w", err)
	}

	return migrationName, body, nil
}
