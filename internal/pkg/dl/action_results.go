// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

func CreateActionResult(ctx context.Context, bulker bulk.Bulk, acr model.ActionResult) error {
	return createActionResult(ctx, bulker, FleetActionsResults, acr)
}

func createActionResult(ctx context.Context, bulker bulk.Bulk, index string, acr model.ActionResult) error {
	if acr.Timestamp == "" {
		acr.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	body, err := json.Marshal(acr)
	if err != nil {
		return err
	}

	_, err = bulker.Create(ctx, index, acr.ActionID+":"+acr.AgentID, body, bulk.WithRefresh())
	if errors.Is(err, es.ErrElasticVersionConflict) {
		return nil
	}
	return err
}
