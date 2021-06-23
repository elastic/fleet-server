// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import (
	"context"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dsl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
)

func Search(ctx context.Context, bulker bulk.Bulk, tmpl *dsl.Tmpl, index string, params map[string]interface{}) (*es.HitsT, error) {
	query, err := tmpl.Render(params)
	if err != nil {
		return nil, err
	}

	res, err := bulker.Search(ctx, index, query)
	if err != nil {
		return nil, err
	}

	return &res.HitsT, nil
}

func SearchWithOneParam(ctx context.Context, bulker bulk.Bulk, tmpl *dsl.Tmpl, index string, name string, v interface{}) (*es.HitsT, error) {
	query, err := tmpl.RenderOne(name, v)
	if err != nil {
		return nil, err
	}
	res, err := bulker.Search(ctx, index, query)
	if err != nil {
		return nil, err
	}

	return &res.HitsT, nil
}
