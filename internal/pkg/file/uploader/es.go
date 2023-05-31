// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package uploader

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dsl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/file"
	"github.com/elastic/fleet-server/v7/internal/pkg/file/cbor"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/rs/zerolog/log"
)

const (
	// integration name is substituted in
	UploadHeaderIndexPattern = ".fleet-files-%s"
	UploadDataIndexPattern   = ".fleet-file-data-%s"
)

var (
	MatchChunkByBID = prepareQueryChunkByBID()
)

func prepareQueryChunkByBID() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()
	root := dsl.NewRoot()
	root.Query().Term(file.FieldBaseID, tmpl.Bind(file.FieldBaseID), nil)
	tmpl.MustResolve(root)
	return tmpl
}

/*
	Metadata Doc Operations
*/

func CreateFileDoc(ctx context.Context, bulker bulk.Bulk, doc []byte, source string, fileID string) (string, error) {
	return bulker.Create(ctx, fmt.Sprintf(UploadHeaderIndexPattern, source), fileID, doc, bulk.WithRefresh())
}

func UpdateFileDoc(ctx context.Context, bulker bulk.Bulk, source string, fileID string, data []byte) error {
	return bulker.Update(ctx, fmt.Sprintf(UploadHeaderIndexPattern, source), fileID, data)
}

/*
	Chunk Operations
*/

func IndexChunk(ctx context.Context, client *elasticsearch.Client, body *cbor.ChunkEncoder, source string, docID string, chunkNum int) error {
	resp, err := client.Index(fmt.Sprintf(UploadDataIndexPattern, source), body, func(req *esapi.IndexRequest) {
		req.DocumentID = fmt.Sprintf("%s.%d", docID, chunkNum)
		if req.Header == nil {
			req.Header = make(http.Header)
		}
		req.Header.Set("Content-Type", "application/cbor")
		req.Header.Set("Accept", "application/json")
		req.Refresh = "true"
	})
	if err != nil {
		return err
	}

	var response ChunkUploadResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return err
	}
	log.Trace().Int("statuscode", resp.StatusCode).Interface("chunk-response", response).Msg("uploaded chunk")

	if response.Error.Type != "" {
		return fmt.Errorf("%s: %s caused by %s: %s", response.Error.Type, response.Error.Reason, response.Error.Cause.Type, response.Error.Cause.Reason)
	}
	return nil
}

type ChunkUploadResponse struct {
	Index   string `json:"_index"`
	ID      string `json:"_id"`
	Result  string `json:"result"`
	Version int    `json:"_version"`
	Shards  struct {
		Total   int `json:"total"`
		Success int `json:"successful"`
		Failed  int `json:"failed"`
	} `json:"_shards"`
	Error es.ErrorT `json:"error"`
}

func DeleteChunk(ctx context.Context, bulker bulk.Bulk, source string, fileID string, chunkNum int) error {
	return bulker.Delete(ctx, fmt.Sprintf(UploadDataIndexPattern, source), fmt.Sprintf("%s.%d", fileID, chunkNum))
}

func DeleteChunksByQuery(ctx context.Context, bulker bulk.Bulk, source string, baseID string) error {
	q, err := MatchChunkByBID.Render(map[string]interface{}{
		file.FieldBaseID: baseID,
	})
	if err != nil {
		return err
	}
	_, err = bulker.Client().DeleteByQuery([]string{fmt.Sprintf(UploadDataIndexPattern, source)}, bytes.NewReader(q))
	return err
}
