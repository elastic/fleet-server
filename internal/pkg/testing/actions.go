// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// +build integration

package testing

import (
	"context"
	"encoding/json"
	"fleet/internal/pkg/bulk"
	"fleet/internal/pkg/es"
	"fleet/internal/pkg/model"
	"fleet/internal/pkg/rnd"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/rs/xid"
)

func CreateRandomActions(min, max int) ([]model.Action, error) {
	r := rnd.New()

	sz := r.Int(min, max)
	agentIds := make([]string, sz)
	for i := 0; i < sz; i++ {
		agentIds[i] = uuid.Must(uuid.NewV4()).String()
	}

	sz = r.Int(4, 9)

	now := time.Now().UTC()

	actions := make([]model.Action, sz)

	for i := 0; i < sz; i++ {
		start := r.Int(0, len(agentIds))
		end := start + r.Int(0, len(agentIds)-start)

		payload := map[string]interface{}{
			uuid.Must(uuid.NewV4()).String(): uuid.Must(uuid.NewV4()).String(),
		}

		data, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}

		aid := agentIds[start:end]
		if len(aid) == 0 {
			aid = nil
		}
		action := model.Action{
			ESDocument: model.ESDocument{
				Id: xid.New().String(),
			},
			ActionId:   uuid.Must(uuid.NewV4()).String(),
			Timestamp:  r.Time(now, 2, 5, time.Second, rnd.TimeBefore).Format(time.RFC3339),
			Expiration: r.Time(now, 12, 25, time.Minute, rnd.TimeAfter).Format(time.RFC3339),
			Type:       "APP_ACTION",
			InputId:    "osquery",
			Agents:     aid,
			Data:       data,
		}

		actions[i] = action
	}
	return actions, nil
}

func StoreRandomActions(ctx context.Context, bulker bulk.Bulk, index string, min, max int) ([]model.Action, error) {
	actions, err := CreateRandomActions(min, max)
	if err != nil {
		return nil, err
	}

	for _, action := range actions {
		body, err := json.Marshal(action)
		if err != nil {
			return nil, err
		}
		_, err = bulker.Create(ctx, index, action.Id, body, bulk.WithRefresh())
		if err != nil {
			return nil, err
		}
	}
	return actions, err
}

func SetupActions(ctx context.Context, t *testing.T, min, max int) (string, bulk.Bulk, []model.Action) {
	index, bulker := SetupIndexWithBulk(ctx, t, es.MappingAction)
	actions, err := StoreRandomActions(ctx, bulker, index, min, max)
	if err != nil {
		t.Fatal(err)
	}

	return index, bulker, actions
}
