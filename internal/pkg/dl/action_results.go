// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import (
	"context"
	"encoding/json"
	"fleet-server/internal/pkg/bulk"
	"fleet-server/internal/pkg/model"
	"time"
)

func CreateActionResult(ctx context.Context, bulker bulk.Bulk, acr model.ActionResult) (string, error) {
	return createActionResult(ctx, bulker, FleetActionsResults, acr)
}

func createActionResult(ctx context.Context, bulker bulk.Bulk, index string, acr model.ActionResult) (string, error) {
	if acr.Timestamp == "" {
		acr.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	body, err := json.Marshal(acr)
	if err != nil {
		return "", nil
	}

	return bulker.Create(ctx, index, acr.Id, body, bulk.WithRefresh())
}
