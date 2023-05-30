// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package uploader

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/uploader/upload"
)

// retrieves upload metadata info from elasticsearch
func FetchUploadInfo(ctx context.Context, bulker bulk.Bulk, uploadID string) (upload.Info, error) {
	results, err := GetFileDoc(ctx, bulker, uploadID)
	if err != nil {
		return upload.Info{}, err
	}
	if len(results) == 0 {
		return upload.Info{}, ErrInvalidUploadID
	}
	if len(results) > 1 {
		return upload.Info{}, fmt.Errorf("unable to locate upload record, got %d records, expected 1", len(results))
	}

	var fi FileMetaDoc
	if err := json.Unmarshal(results[0].Source, &fi); err != nil {
		return upload.Info{}, fmt.Errorf("file meta doc parsing error: %w", err)
	}

	// calculate number of chunks required
	cnt := fi.File.Size / fi.File.ChunkSize
	if fi.File.Size%fi.File.ChunkSize > 0 {
		cnt += 1
	}

	return upload.Info{
		ID:        fi.UploadID,
		Source:    fi.Source,
		AgentID:   fi.AgentID,
		ActionID:  fi.ActionID,
		DocID:     results[0].ID,
		ChunkSize: fi.File.ChunkSize,
		Total:     fi.File.Size,
		Count:     int(cnt),
		Start:     fi.Start,
		Status:    upload.Status(fi.File.Status),
	}, nil
}

func SetStatus(ctx context.Context, bulker bulk.Bulk, info upload.Info, status upload.Status) error {
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

func MarkComplete(ctx context.Context, bulker bulk.Bulk, info upload.Info, hash string) error {
	data, err := json.Marshal(map[string]interface{}{
		"doc": map[string]interface{}{
			"file": map[string]string{
				"Status": string(upload.StatusDone),
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
