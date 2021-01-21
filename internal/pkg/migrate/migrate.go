// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package migrate

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/saved"
	"github.com/rs/zerolog"
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
func Migrate(ctx context.Context, log zerolog.Logger, sv saved.CRUD, bulker bulk.Bulk) error {
	return MigrateEnrollmentAPIKeys(ctx, log, sv, bulker)
}

func MigrateEnrollmentAPIKeys(ctx context.Context, log zerolog.Logger, sv saved.CRUD, bulker bulk.Bulk) error {

	// Query all enrollment keys from the new schema
	raw, err := dl.RenderAllEnrollmentAPIKeysQuery(1000)
	if err != nil {
		return err
	}

	var recs []model.EnrollmentApiKey
	var resHits []es.HitT
	res, err := bulker.Search(ctx, []string{dl.FleetEnrollmentAPIKeys}, raw, bulk.WithRefresh())
	if err != nil {
		if errors.Is(err, es.ErrIndexNotFound) {
			log.Debug().Str("index", dl.FleetEnrollmentAPIKeys).Msg(es.ErrIndexNotFound.Error())
			// Continue with migration if the .fleet-enrollment-api-keys index is not found
			err = nil
		} else {
			return err
		}
	} else {
		resHits = res.Hits
	}

	for _, hit := range resHits {
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
