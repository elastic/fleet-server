// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import (
	"context"
	"encoding/json"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dsl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/rs/zerolog"
)

var (
	QueryArtifactTmpl = prepareQueryArtifact()
)

func prepareQueryArtifact() *dsl.Tmpl {
	root := dsl.NewRoot()
	tmpl := dsl.NewTmpl()

	must := root.Query().Bool().Must()
	must.Term(FieldDecodedSha256, tmpl.Bind(FieldDecodedSha256), nil)
	must.Term(FieldIdentifier, tmpl.Bind(FieldIdentifier), nil)
	tmpl.MustResolve(root)
	return tmpl
}

func FindArtifact(ctx context.Context, bulker bulk.Bulk, ident, sha2 string) (*model.Artifact, error) {

	params := map[string]interface{}{
		FieldDecodedSha256: sha2,
		FieldIdentifier:    ident,
	}

	res, err := Search(
		ctx,
		bulker,
		QueryArtifactTmpl,
		FleetArtifacts,
		params,
	)

	if err != nil {
		return nil, err
	}

	if len(res.Hits) == 0 {
		return nil, ErrNotFound
	}

	if len(res.Hits) > 1 {
		zerolog.Ctx(ctx).Warn().
			Str("ident", ident).
			Str("sha2", sha2).
			Int("cnt", len(res.Hits)).
			Str("used", res.Hits[0].ID).
			Msg("Multiple HITS on artifact query.  Using the first returned.")
	}

	// deserialize
	var artifact model.Artifact
	if err = json.Unmarshal(res.Hits[0].Source, &artifact); err != nil {
		return nil, err
	}

	return &artifact, nil
}
