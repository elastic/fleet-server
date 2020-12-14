// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import (
	"context"
	"fleet/internal/pkg/bulk"
	"fleet/internal/pkg/dsl"
	"fleet/internal/pkg/model"
	"fmt"
)

const (
	FieldApiKeyID = "api_key_id"
)

var (
	QueryEnrollmentAPIKeyByID = prepareFindEnrollmentAPIKeyByID()
)

// RenderAllEnrollmentAPIKeysQuery render all enrollment api keys query. For migration only.
func RenderAllEnrollmentAPIKeysQuery(size uint64) ([]byte, error) {
	tmpl := dsl.NewTmpl()

	root := dsl.NewRoot()
	root.Size(size)

	err := tmpl.Resolve(root)
	if err != nil {
		return nil, err
	}
	return tmpl.Render(nil)
}

func prepareFindEnrollmentAPIKeyByID() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()

	root := dsl.NewRoot()
	root.Query().Bool().Filter().Term(FieldApiKeyID, tmpl.Bind(FieldApiKeyID), nil)

	tmpl.MustResolve(root)
	return tmpl
}

func FindEnrollmentAPIKey(ctx context.Context, bulker bulk.Bulk, tmpl *dsl.Tmpl, id string) (rec model.EnrollmentApiKey, err error) {
	return findEnrollmentAPIKey(ctx, bulker, FleetEnrollmentAPIKeys, tmpl, id)
}

func findEnrollmentAPIKey(ctx context.Context, bulker bulk.Bulk, index string, tmpl *dsl.Tmpl, id string) (rec model.EnrollmentApiKey, err error) {
	res, err := SearchWithOneParam(ctx, bulker, tmpl, index, FieldApiKeyID, id)
	if err != nil {
		return
	}

	sz := len(res.Hits)
	if sz != 1 {
		return rec, fmt.Errorf("hit count mismatch %v", sz)
	}

	err = res.Hits[0].Unmarshal(&rec)
	return rec, err
}
