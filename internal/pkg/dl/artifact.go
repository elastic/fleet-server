// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dsl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

const (
	artifactsIndexName = ".fleet-artifacts"
)

var (
	QueryArtifactBySha2 = prepareQueryArtifactBySha2()
	ErrConflict         = errors.New("Fail multiple artifacts for the same sha256")
)

func prepareQueryArtifactBySha2() *dsl.Tmpl {
	root := dsl.NewRoot()
	tmpl := dsl.NewTmpl()

	root.Query().Bool().Filter().Term(FieldEncodedSha256, tmpl.Bind(FieldEncodedSha256), nil)
	tmpl.MustResolve(root)
	return tmpl
}

func FindArtifactBySha256(ctx context.Context, bulker bulk.Bulk, sha2 string) (*model.Artifact, error) {

	res, err := SearchWithOneParam(
		ctx,
		bulker,
		QueryArtifactBySha2,
		artifactsIndexName,
		FieldEncodedSha256,
		sha2,
	)

	if err != nil {
		return nil, err
	}

	if len(res.Hits) == 0 {
		return nil, ErrNotFound
	}

	if len(res.Hits) > 1 {
		return nil, ErrConflict
	}

	// deserialize
	var artifact model.Artifact
	if err = json.Unmarshal(res.Hits[0].Source, &artifact); err != nil {
		return nil, err
	}

	return &artifact, nil
}
