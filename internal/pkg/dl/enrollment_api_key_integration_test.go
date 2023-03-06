// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

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
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
)

func createRandomEnrollmentAPIKey(policyID string, active bool) model.EnrollmentAPIKey {
	now := time.Now().UTC()
	return model.EnrollmentAPIKey{
		ESDocument: model.ESDocument{
			Id: xid.New().String(),
		},
		Active:    active,
		APIKey:    "d2JndlFIWUJJUVVxWDVia2NJTV86X0d6ZmljZGNTc1d4R1otbklrZFFRZw==",
		APIKeyID:  xid.New().String(),
		CreatedAt: now.Format(time.RFC3339),
		Name:      "Default (db3f8318-05f0-4625-a808-9deddb0112b5)",
		PolicyID:  policyID,
	}

}

func storeRandomEnrollmentAPIKey(ctx context.Context, bulker bulk.Bulk, index string, policyID string, active bool) (rec model.EnrollmentAPIKey, err error) {
	rec = createRandomEnrollmentAPIKey(policyID, active)

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

	index, bulker := ftesting.SetupCleanIndex(ctx, t, FleetEnrollmentAPIKeys)

	rec, err := storeRandomEnrollmentAPIKey(ctx, bulker, index, uuid.Must(uuid.NewV4()).String(), true)
	if err != nil {
		t.Fatal(err)
	}
	foundRec, err := findEnrollmentAPIKey(ctx, bulker, index, QueryEnrollmentAPIKeyByID, FieldAPIKeyID, rec.APIKeyID)
	if err != nil {
		t.Fatal(err)
	}

	diff := cmp.Diff(rec, foundRec)
	if diff != "" {
		t.Fatal(diff)
	}

	_, err = findEnrollmentAPIKey(ctx, bulker, index, QueryEnrollmentAPIKeyByID, FieldAPIKeyID, xid.New().String())
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
	t.Skip("Flaky test see https://github.com/elastic/fleet-server/issues/1289")
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	index, bulker := ftesting.SetupCleanIndex(ctx, t, FleetEnrollmentAPIKeys)

	policyID := uuid.Must(uuid.NewV4()).String()
	rec1, err := storeRandomEnrollmentAPIKey(ctx, bulker, index, policyID, true)
	if err != nil {
		t.Fatal(err)
	}
	rec2, err := storeRandomEnrollmentAPIKey(ctx, bulker, index, policyID, true)
	if err != nil {
		t.Fatal(err)
	}
	_, err = storeRandomEnrollmentAPIKey(ctx, bulker, index, uuid.Must(uuid.NewV4()).String(), true)
	if err != nil {
		t.Fatal(err)
	}

	foundRecs, err := findEnrollmentAPIKeys(ctx, bulker, index, QueryEnrollmentAPIKeyByPolicyID, FieldPolicyID, policyID)
	if err != nil {
		t.Fatal(err)
	}

	diff := cmp.Diff([]model.EnrollmentAPIKey{rec1, rec2}, foundRecs)
	if diff != "" {
		t.Fatal(diff)
	}
}

func TestSearchEnrollmentAPIKeyByPolicyIDWithInactiveIDs(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	index, bulker := ftesting.SetupCleanIndex(ctx, t, FleetEnrollmentAPIKeys)

	policyID := uuid.Must(uuid.NewV4()).String()
	rec, err := storeRandomEnrollmentAPIKey(ctx, bulker, index, policyID, true)
	if err != nil {
		t.Fatalf("unable to store enrollment key: %v", err)
	}
	for i := 0; i < 10; i++ {
		_, err = storeRandomEnrollmentAPIKey(ctx, bulker, index, uuid.Must(uuid.NewV4()).String(), false)
		if err != nil {
			t.Fatalf("unable to store enrollment key: %v", err)
		}
	}

	foundRecs, err := findEnrollmentAPIKeys(ctx, bulker, index, QueryEnrollmentAPIKeyByPolicyID, FieldPolicyID, policyID)
	if err != nil {
		t.Fatalf("unable to find enrollment key: %v", err)
	}

	diff := cmp.Diff([]model.EnrollmentAPIKey{rec}, foundRecs)
	if diff != "" {
		t.Fatalf("expected content does not match: %v", diff)
	}
}
