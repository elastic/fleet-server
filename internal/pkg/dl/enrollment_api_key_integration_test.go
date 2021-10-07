// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration
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

func createRandomEnrollmentAPIKey(policyID string) model.EnrollmentApiKey {
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
		PolicyId:  policyID,
	}

}

func storeRandomEnrollmentAPIKey(ctx context.Context, bulker bulk.Bulk, index string, policyID string) (rec model.EnrollmentApiKey, err error) {
	rec = createRandomEnrollmentAPIKey(policyID)

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

func TestSearchEnrollmentAPIKeyByID(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	index, bulker := ftesting.SetupIndexWithBulk(ctx, t, es.MappingEnrollmentApiKey)
	rec, err := storeRandomEnrollmentAPIKey(ctx, bulker, index, uuid.Must(uuid.NewV4()).String())
	if err != nil {
		t.Fatal(err)
	}
	foundRec, err := findEnrollmentAPIKey(ctx, bulker, index, QueryEnrollmentAPIKeyByID, FieldApiKeyID, rec.ApiKeyId)
	if err != nil {
		t.Fatal(err)
	}

	diff := cmp.Diff(rec, foundRec)
	if diff != "" {
		t.Fatal(diff)
	}

	foundRec, err = findEnrollmentAPIKey(ctx, bulker, index, QueryEnrollmentAPIKeyByID, FieldApiKeyID, xid.New().String())
	if err == nil {
		t.Fatal("expected error")
	} else {
		diff := cmp.Diff(err.Error(), "hit count mismatch 0")
		if diff != "" {
			t.Fatal(diff)
		}
	}
}

func TestSearchEnrollmentAPIKeyByPolicyID(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	index, bulker := ftesting.SetupIndexWithBulk(ctx, t, es.MappingEnrollmentApiKey)

	policyID := uuid.Must(uuid.NewV4()).String()
	rec1, err := storeRandomEnrollmentAPIKey(ctx, bulker, index, policyID)
	if err != nil {
		t.Fatal(err)
	}
	rec2, err := storeRandomEnrollmentAPIKey(ctx, bulker, index, policyID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = storeRandomEnrollmentAPIKey(ctx, bulker, index, uuid.Must(uuid.NewV4()).String())
	if err != nil {
		t.Fatal(err)
	}

	foundRecs, err := findEnrollmentAPIKeys(ctx, bulker, index, QueryEnrollmentAPIKeyByPolicyID, FieldPolicyId, policyID)
	if err != nil {
		t.Fatal(err)
	}

	diff := cmp.Diff([]model.EnrollmentApiKey{rec1, rec2}, foundRecs)
	if diff != "" {
		t.Fatal(diff)
	}
}
