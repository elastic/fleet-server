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

func Migrate(ctx context.Context, bulker bulk.Bulk) error {
	return migrateAgentMetadata(ctx, bulker)
}

// FleetServer 7.15 added a new *AgentMetadata field to the Agent record.
// This field was populated in new enrollments in 7.15 and later; however, the
// change was not backported to support 7.14.  The security team is reliant on the
// existence of this field in 7.16, so the following migration was added to
// support upgrade from 7.14.
//
// It is currently safe to run this in the background; albeit with some
// concern on conflicts.  The conflict risk exists regardless as N Fleet Servers
// can be run in parallel at the same time.
//
// As the update only occurs once, the 99.9% case is a noop.
func migrateAgentMetadata(ctx context.Context, bulker bulk.Bulk) error {

	root := dsl.NewRoot()
	root.Query().Bool().MustNot().Exists("agent.id")

	painless := "ctx._source.agent = [:]; ctx._source.agent.id = ctx._id;"
	root.Param("script", painless)

	body, err := root.MarshalJSON()
	if err != nil {
		return err
	}

LOOP:
	for {
		nConflicts, err := updateAgentMetadata(ctx, bulker, body)
		if err != nil {
			return err
		}
		if nConflicts == 0 {
			break LOOP
		}

		time.Sleep(time.Second)
	}

	return nil
}

func updateAgentMetadata(ctx context.Context, bulker bulk.Bulk, body []byte) (int, error) {
	start := time.Now()

	client := bulker.Client()

	reader := bytes.NewReader(body)

	opts := []func(*esapi.UpdateByQueryRequest){
		client.UpdateByQuery.WithBody(reader),
		client.UpdateByQuery.WithContext(ctx),
		client.UpdateByQuery.WithConflicts("proceed"),
	}

	res, err := client.UpdateByQuery([]string{FleetAgents}, opts...)

	if err != nil {
		return 0, err
	}

	if res.IsError() {
		if res.StatusCode == http.StatusNotFound {
			// Ignore index not created yet; nothing to upgrade
			return 0, nil
		}

		return 0, fmt.Errorf("Migrate UpdateByQuery %s", res.String())
	}

	resp := struct {
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
	}{}

	decoder := json.NewDecoder(res.Body)
	if err := decoder.Decode(&resp); err != nil {
		return 0, errors.Wrap(err, "decode UpdateByQuery response")
	}

	log.Info().
		Int("took", resp.Took).
		Bool("timed_out", resp.TimedOut).
		Int("total", resp.Total).
		Int("updated", resp.Updated).
		Int("deleted", resp.Deleted).
		Int("batches", resp.Batches).
		Int("version_conflicts", resp.VersionConflicts).
		Int("noops", resp.Noops).
		Int("retries.bulk", resp.Retries.Bulk).
		Int("retries.search", resp.Retries.Search).
		Dur("rtt", time.Since(start)).
		Msg("migrate agent records response")

	for _, fail := range resp.Failures {
		log.Error().RawJSON("failure", fail).Msg("migration failure")
	}

	return resp.VersionConflicts, err
}
