// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import (
	"context"
	"encoding/json"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

func CreateUploadInfo(ctx context.Context, bulker bulk.Bulk, fi model.FileInfo) (string, error) {
	return createUploadInfo(ctx, bulker, "files", fi) // @todo: index destination is an input (and different per integration)
}

func createUploadInfo(ctx context.Context, bulker bulk.Bulk, index string, fi model.FileInfo) (string, error) {
	body, err := json.Marshal(fi)
	if err != nil {
		return "", err
	}

	// @todo: proper doc ID
	return bulker.Create(ctx, index, "", body, bulk.WithRefresh())
}
