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

	"github.com/gofrs/uuid"
	"github.com/google/go-cmp/cmp"
	"github.com/rs/xid"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/rnd"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
)

func createRandomActionResults() ([]model.ActionResult, error) {
	r := rnd.New()

	sz := r.Int(1, 9)

	now := time.Now().UTC()

	results := make([]model.ActionResult, sz)

	for i := 0; i < sz; i++ {
		payload := map[string]interface{}{
			uuid.Must(uuid.NewV4()).String(): uuid.Must(uuid.NewV4()).String(),
		}

		data, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}

		var errmsg string
		if r.Bool() {
			errmsg = "random error " + uuid.Must(uuid.NewV4()).String()
		}
		result := model.ActionResult{
			ESDocument: model.ESDocument{
				Id: xid.New().String(),
			},
			Timestamp: r.Time(now, 2, 5, time.Second, rnd.TimeBefore).Format(time.RFC3339),
			AgentId:   uuid.Must(uuid.NewV4()).String(),
			ActionId:  uuid.Must(uuid.NewV4()).String(),
			Error:     errmsg,
			Data:      data,
		}

		results[i] = result
	}
	return results, nil
}

func storeRandomActionResults(ctx context.Context, bulker bulk.Bulk, index string) ([]model.ActionResult, error) {
	results, err := createRandomActionResults()
	if err != nil {
		return nil, err
	}

	for _, result := range results {
		_, err = createActionResult(ctx, bulker, index, result)
		if err != nil {
			return nil, err
		}
	}
	return results, err
}

func setupActionResults(ctx context.Context, t *testing.T) (string, bulk.Bulk, []model.ActionResult) {
	index, bulker := ftesting.SetupIndexWithBulk(ctx, t, es.MappingActionResult)
	results, err := storeRandomActionResults(ctx, bulker, index)
	if err != nil {
		t.Fatal(err)
	}

	return index, bulker, results
}

type ActionsResults []model.ActionResult

func (acrs ActionsResults) find(ar model.ActionResult) *model.ActionResult {
	for _, acr := range acrs {
		if acr.ActionId == ar.ActionId {
			return &acr
		}
	}
	return nil
}

func TestActionResultsStored(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	index, bulker, acrs := setupActionResults(ctx, t)

	res, err := bulker.Search(ctx, index, []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}

	hits := res.Hits

	diff := cmp.Diff(len(acrs), len(hits))
	if diff != "" {
		t.Fatal(diff)
	}

	for _, hit := range hits {
		var actionResult model.ActionResult
		err = hit.Unmarshal(&actionResult)
		if err != nil {
			t.Fatal(err)
		}

		found := ActionsResults(acrs).find(actionResult)
		if found == nil {
			t.Fatal("action result is not found")
		} else {
			diff := cmp.Diff(*found, actionResult)
			if diff != "" {
				t.Fatal(diff)
			}
		}
	}
}
