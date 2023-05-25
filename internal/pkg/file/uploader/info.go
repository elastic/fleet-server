// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package uploader

import (
	"context"
	"encoding/json"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/file"
)

func SetStatus(ctx context.Context, bulker bulk.Bulk, info file.Info, status file.Status) error {
	data, err := json.Marshal(map[string]interface{}{
		"doc": map[string]interface{}{
			"file": map[string]string{
				"Status": string(status),
			},
		},
	})
	if err != nil {
		return err
	}
	return UpdateFileDoc(ctx, bulker, info.Source, info.DocID, data)
}

func MarkComplete(ctx context.Context, bulker bulk.Bulk, info file.Info, hash string) error {
	data, err := json.Marshal(map[string]interface{}{
		"doc": map[string]interface{}{
			"file": map[string]string{
				"Status": string(file.StatusDone),
			},
			"transithash": map[string]interface{}{
				"sha256": hash,
			},
		},
	})
	if err != nil {
		return err
	}
	return UpdateFileDoc(ctx, bulker, info.Source, info.DocID, data)
}
