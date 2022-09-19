// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package esutil

import (
	"context"

	"github.com/elastic/go-elasticsearch/v7"
)

// EnsureIndex sets up the index if it doesn't exists, utilized for integration tests at the moment
func EnsureIndex(ctx context.Context, cli *elasticsearch.Client, name, mapping string) error {
	err := EnsureTemplate(ctx, cli, name, mapping, false)
	if err != nil {
		return err
	}
	return CreateIndex(ctx, cli, name)
}
