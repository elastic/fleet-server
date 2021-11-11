// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration
// +build integration

package testing

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/rnd"

	"github.com/gofrs/uuid"
	"github.com/rs/xid"
)

type CreateActionsConfig struct {
	minAgentsCount   int
	maxAgentsCount   int
	minActionsCount  int
	maxActionsCount  int
	timestampOffset  time.Duration // offset for the action timestamp from the current time
	expirationOffset time.Duration // expiration offset since the action creation
}

type CreateActionsOpt func(c *CreateActionsConfig)

func CreateActionsWithMinAgentsCount(count int) CreateActionsOpt {
	return func(c *CreateActionsConfig) {
		c.minAgentsCount = count
	}
}

func CreateActionsWithMaxAgentsCount(count int) CreateActionsOpt {
	return func(c *CreateActionsConfig) {
		c.maxAgentsCount = count
	}
}

func CreateActionsWithMinActionsCount(count int) CreateActionsOpt {
	return func(c *CreateActionsConfig) {
		c.minActionsCount = count
	}
}

func CreateActionsWithMaxActionsCount(count int) CreateActionsOpt {
	return func(c *CreateActionsConfig) {
		c.maxActionsCount = count
	}
}

func CreateActionsWithTimestampOffset(timestampOffset time.Duration) CreateActionsOpt {
	return func(c *CreateActionsConfig) {
		c.timestampOffset = timestampOffset
	}
}

func CreateActionsWithExpirationOffset(expirationOffset time.Duration) CreateActionsOpt {
	return func(c *CreateActionsConfig) {
		c.expirationOffset = expirationOffset
	}
}

func CreateRandomActions(opts ...CreateActionsOpt) ([]model.Action, error) {
	c := CreateActionsConfig{
		minAgentsCount:   1,
		maxAgentsCount:   1,
		minActionsCount:  4,               // previously hardcoded, using as default
		maxActionsCount:  9,               // previously hardcoded, using as default
		expirationOffset: 5 * time.Minute, // default expiration of the action since the action timestamp
	}

	for _, opt := range opts {
		opt(&c)
	}

	r := rnd.New()

	sz := r.Int(c.minAgentsCount, c.maxAgentsCount)
	agentIds := make([]string, sz)
	for i := 0; i < sz; i++ {
		agentIds[i] = uuid.Must(uuid.NewV4()).String()
	}

	sz = r.Int(c.minActionsCount, c.maxActionsCount)

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

		timestamp := r.Time(now, 1, 3, time.Second, rnd.TimeBefore)
		if c.timestampOffset != 0 {
			timestamp = timestamp.Add(c.timestampOffset)
		}

		expiration := timestamp.Add(c.expirationOffset)

		action := model.Action{
			ESDocument: model.ESDocument{
				Id: xid.New().String(),
			},
			ActionId:   uuid.Must(uuid.NewV4()).String(),
			Timestamp:  timestamp.Format(time.RFC3339),
			Expiration: expiration.Format(time.RFC3339),
			Type:       "APP_ACTION",
			InputType:  "osquery",
			Agents:     aid,
			Data:       data,
		}

		actions[i] = action
	}
	return actions, nil

}

func StoreRandomActions(ctx context.Context, bulker bulk.Bulk, index string, min, max int) ([]model.Action, error) {
	actions, err := CreateRandomActions(
		CreateActionsWithMinAgentsCount(min),
		CreateActionsWithMaxAgentsCount(max),
	)
	if err != nil {
		return nil, err
	}

	return actions, StoreActions(ctx, bulker, index, actions)
}

func StoreActions(ctx context.Context, bulker bulk.Bulk, index string, actions []model.Action) error {
	for _, action := range actions {
		body, err := json.Marshal(action)
		if err != nil {
			return err
		}
		_, err = bulker.Create(ctx, index, action.Id, body, bulk.WithRefresh())
		if err != nil {
			return err
		}
	}
	return nil
}

func SetupActions(ctx context.Context, t *testing.T, min, max int) (string, bulk.Bulk, []model.Action) {
	index, bulker := SetupIndexWithBulk(ctx, t, es.MappingAction)
	actions, err := StoreRandomActions(ctx, bulker, index, min, max)
	if err != nil {
		t.Fatal(err)
	}

	return index, bulker, actions
}
