// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package uploader

import (
	"context"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/file"
)

func SetStatus(ctx context.Context, bulker bulk.Bulk, info file.Info, status file.Status) error {
	return UpdateFileDoc(ctx, bulker, info.Source, info.DocID, status, "")
}

func MarkComplete(ctx context.Context, bulker bulk.Bulk, info file.Info, hash string) error {
	return UpdateFileDoc(ctx, bulker, info.Source, info.DocID, file.StatusDone, hash)
}
