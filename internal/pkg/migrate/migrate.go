// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package migrate

import (
	"context"
	"encoding/json"
	"fleet/internal/pkg/bulk"
	"fleet/internal/pkg/dl"
	"fleet/internal/pkg/model"
	"fleet/internal/pkg/saved"
)

type enrollmentApiKey struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	ApiKey    string `json:"api_key" saved:"encrypt"`
	ApiKeyId  string `json:"api_key_id"`
	PolicyId  string `json:"policy_id"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	ExpireAt  string `json:"expire_at"`
	Active    bool   `json:"active"`
}

// Data migration
// This is for development only (1 instance of fleet)
// Not safe for multiple instances of fleet
// Initially needed to migrate the enrollment-api-keys that kibana creates
func Migrate(ctx context.Context, sv saved.CRUD, bulker bulk.Bulk) error {
	return MigrateEnrollmentAPIKeys(ctx, sv, bulker)
}

func MigrateEnrollmentAPIKeys(ctx context.Context, sv saved.CRUD, bulker bulk.Bulk) error {

	// Query all enrollment keys from the new schema
	raw, err := dl.RenderAllEnrollmentAPIKeysQuery(1000)
	if err != nil {
		return err
	}

	var recs []model.EnrollmentApiKey
	res, err := bulker.Search(ctx, []string{dl.FleetEnrollmentAPIKeys}, raw, bulk.WithRefresh())
	if err != nil {
		return err
	}

	for _, hit := range res.Hits {
		var rec model.EnrollmentApiKey
		err := json.Unmarshal(hit.Source, &rec)
		if err != nil {
			return err
		}
		recs = append(recs, rec)
	}

	// Query enrollment keys from kibana saved objects
	query := saved.NewQuery("fleet-enrollment-api-keys")

	hits, err := sv.FindByNode(ctx, query)
	if err != nil {
		return err
	}

	for _, hit := range hits {
		var rec enrollmentApiKey
		if err := sv.Decode(hit, &rec); err != nil {
			return err
		}
		if _, ok := findExistingEnrollmentAPIKey(recs, rec); !ok {
			newRec := translateEnrollmentAPIKey(rec)
			b, err := json.Marshal(newRec)
			if err != nil {
				return err
			}
			_, err = bulker.Create(ctx, dl.FleetEnrollmentAPIKeys, "", b, bulk.WithRefresh())
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func findExistingEnrollmentAPIKey(hay []model.EnrollmentApiKey, needle enrollmentApiKey) (*model.EnrollmentApiKey, bool) {
	for _, rec := range hay {
		if rec.ApiKeyId == needle.ApiKeyId {
			return &rec, true
		}
	}
	return nil, false
}

func translateEnrollmentAPIKey(src enrollmentApiKey) model.EnrollmentApiKey {
	return model.EnrollmentApiKey{
		Active:    src.Active,
		ApiKey:    src.ApiKey,
		ApiKeyId:  src.ApiKeyId,
		CreatedAt: src.CreatedAt,
		ExpireAt:  src.ExpireAt,
		Name:      src.Name,
		PolicyId:  src.PolicyId,
		UpdatedAt: src.UpdatedAt,
	}
}
