// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import (
	"context"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"

	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

func MigrateAgent(ctx context.Context, zlog zerolog.Logger, bulker bulk.Bulk, agent *model.Agent) error {

	// Agents enrolled before 7.15 do not have the metadata structure in the record.
	// This metadata record was added to simplify transformations for the security application.
	// If the record exists, there's nothing to do here.
	// NOTE: This logic can be removed when we no longer support upgrade from 7.14.
	if agent.Agent != nil {
		return nil
	}

	// Update the id record, the version will be picked up on the next check-in.
	meta := &model.AgentMetadata{Id: agent.Id}

	now := time.Now().UTC().Format(time.RFC3339)

	doc := bulk.UpdateFields{
		FieldAgent:     meta,
		FieldUpdatedAt: now,
	}

	body, err := doc.Marshal()
	if err != nil {
		return errors.Wrap(err, "migrateAgent marshal")
	}

	if err = bulker.Update(ctx, FleetAgents, agent.Id, body, bulk.WithRefresh()); err != nil {
		zlog.Error().Err(err).Msg("fail migrate agent metadata")
		return errors.Wrap(err, "migrateAgent update")
	}

	agent.Agent = meta

	zlog.Info().Str(logger.AgentId, agent.Id).Msg("migrate agent record metadata")
	return nil
}
