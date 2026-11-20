// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dl

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/rs/zerolog"
)

// CreateActionResult creates an action result document. Options (for example bulk.WithRefresh())
// are passed to the underlying create; no refresh is requested unless asked for.
func CreateActionResult(ctx context.Context, bulker bulk.Bulk, acr model.ActionResult, opts ...bulk.Opt) error {
	return createActionResult(ctx, bulker, FleetActionsResults, acr, opts...)
}

func createActionResult(ctx context.Context, bulker bulk.Bulk, index string, acr model.ActionResult, opts ...bulk.Opt) error {
	if acr.Timestamp == "" {
		acr.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	body, err := json.Marshal(acr)
	if err != nil {
		return err
	}

	id := acr.ActionID + ":" + acr.AgentID
	_, err = bulker.Create(ctx, index, id, body, opts...)
	// ignoring version conflict in case the same action result is tried to be created multiple times (unique id with actionID and agentID)
	if errors.Is(err, es.ErrElasticVersionConflict) {
		zerolog.Ctx(ctx).Debug().Err(err).Str("id", id).Msg("action result already exists, ignoring")
		return nil
	}
	return err
}
