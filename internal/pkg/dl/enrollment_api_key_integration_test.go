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
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
)

func createRandomEnrollmentAPIKey() model.EnrollmentApiKey {
	now := time.Now().UTC()
	return model.EnrollmentApiKey{
		ESDocument: model.ESDocument{
			Id: xid.New().String(),
		},
		Active:    true,
		ApiKey:    "d2JndlFIWUJJUVVxWDVia2NJTV86X0d6ZmljZGNTc1d4R1otbklrZFFRZw==",
		ApiKeyId:  xid.New().String(),
		CreatedAt: now.Format(time.RFC3339),
		Name:      "Default (db3f8318-05f0-4625-a808-9deddb0112b5)",
		PolicyId:  uuid.Must(uuid.NewV4()).String(),
	}

}

func storeRandomEnrollmentAPIKey(ctx context.Context, bulker bulk.Bulk, index string) (rec model.EnrollmentApiKey, err error) {
	rec = createRandomEnrollmentAPIKey()

	body, err := json.Marshal(rec)
	if err != nil {
		return
	}
	_, err = bulker.Create(ctx, index, rec.Id, body, bulk.WithRefresh())
	if err != nil {
		return
	}
	return rec, err
}

func setupEnrollmentAPIKeys(ctx context.Context, t *testing.T) (string, bulk.Bulk, model.EnrollmentApiKey) {
	index, bulker := ftesting.SetupIndexWithBulk(ctx, t, es.MappingEnrollmentApiKey)
	rec, err := storeRandomEnrollmentAPIKey(ctx, bulker, index)
	if err != nil {
		t.Fatal(err)
	}

	return index, bulker, rec
}

func TestSearchEnrollmentAPIKey(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	index, bulker, rec := setupEnrollmentAPIKeys(ctx, t)
	foundRec, err := findEnrollmentAPIKey(ctx, bulker, index, QueryEnrollmentAPIKeyByID, rec.ApiKeyId)
	if err != nil {
		t.Fatal(err)
	}

	diff := cmp.Diff(rec, foundRec)
	if diff != "" {
		t.Fatal(diff)
	}

	foundRec, err = findEnrollmentAPIKey(ctx, bulker, index, QueryEnrollmentAPIKeyByID, xid.New().String())
	if err == nil {
		t.Fatal("expected error")
	} else {
		diff := cmp.Diff(err.Error(), "hit count mismatch 0")
		if diff != "" {
			t.Fatal(diff)
		}
	}
}
