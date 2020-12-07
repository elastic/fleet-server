// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// +build integration

package dl

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"fleet/internal/pkg/bulk"
	"fleet/internal/pkg/config"
	"fleet/internal/pkg/es"
	"fleet/internal/pkg/esboot"
	"fleet/internal/pkg/model"
	"fleet/internal/pkg/rnd"

	"github.com/gofrs/uuid"
	"github.com/google/go-cmp/cmp"
	"github.com/rs/xid"
)

func createRandomActions() ([]model.Action, error) {
	r := rnd.New()

	sz := r.Int(1, 11)
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

		action := model.Action{
			Id:         uuid.Must(uuid.NewV4()).String(),
			Timestamp:  r.Time(now, 2, 5, time.Second, rnd.TimeBefore).Format(time.RFC3339),
			Expiration: r.Time(now, 12, 25, time.Minute, rnd.TimeAfter).Format(time.RFC3339),
			Type:       "APP_ACTION",
			InputId:    "osquery",
			Agents:     agentIds[start:end],
			Data:       data,
		}

		actions[i] = action
	}
	return actions, nil
}

func storeRandomActions(ctx context.Context, bulker bulk.Bulk, index string) ([]model.Action, error) {
	actions, err := createRandomActions()
	if err != nil {
		return nil, err
	}

	for _, action := range actions {
		body, err := json.Marshal(action)
		if err != nil {
			return nil, err
		}
		_, err = bulker.Create(ctx, index, "", body, bulk.WithRefresh())
		if err != nil {
			return nil, err
		}
	}
	return actions, err
}

func setup(ctx context.Context, t *testing.T, index string) (bulk.Bulk, []model.Action) {
	cfg, err := config.LoadFile("../../../fleet-server.yml")
	if err != nil {
		t.Fatal(err)
	}

	cli, err := es.New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}

	err = esboot.EnsureIndex(ctx, cli, index, esboot.MappingAction)
	if err != nil {
		t.Fatal(err)
	}
	actions, err := storeRandomActions(ctx, cli.Bulk(), index)
	if err != nil {
		t.Fatal(err)
	}

	return cli.Bulk(), actions
}

func TestSearchActionsQuery(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	now := time.Now().UTC()

	// temp index name to avoid collisions with other parallel tests
	index := xid.New().String()
	bulker, actions := setup(ctx, t, index)

	t.Run("all agents actions", func(t *testing.T) {
		tmpl, err := PrepareAllAgentActionsQuery()
		if err != nil {
			t.Fatal(err)
		}

		foundActions, err := searchActions(ctx, bulker, tmpl, index, map[string]interface{}{
			FieldSeqNo:      -1,
			FieldMaxSeqNo:   len(actions),
			FieldExpiration: now,
		})
		if err != nil {
			t.Fatal(err)
		}

		diff := cmp.Diff(len(actions), len(foundActions))
		if diff != "" {
			t.Fatal(diff)
		}
	})

}
