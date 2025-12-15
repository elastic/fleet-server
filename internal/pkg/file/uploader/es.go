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
	"github.com/rs/zerolog"
	"go.elastic.co/apm/v2"
)

const (
	// integration name is substituted in
	UploadHeaderIndexPattern = ".fleet-fileds-fromhost-meta-%s"
	UploadDataIndexPattern   = ".fleet-fileds-fromhost-data-%s"
)

var (
	MatchChunkByBID      = prepareQueryChunkByBID()
	MatchChunkByDocument = prepareQueryChunkByDoc()
	UpdateMetaDocByID    = prepareUpdateMetaDoc()
)

func prepareQueryChunkByBID() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()
	root := dsl.NewRoot()
	root.Query().Term(file.FieldBaseID, tmpl.Bind(file.FieldBaseID), nil)
	tmpl.MustResolve(root)
	return tmpl
}

func prepareQueryChunkByDoc() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()
	root := dsl.NewRoot()
	root.Query().Term("_id", tmpl.Bind("_id"), nil)
	tmpl.MustResolve(root)
	return tmpl
}

func prepareUpdateMetaDoc() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()
	root := dsl.NewRoot()
	root.Query().Term("_id", tmpl.Bind("_id"), nil)
	scr := root.Script()

	scr.Param("source", tmpl.Bind("source"))
	scr.Param("lang", "painless")
	prm := scr.Params()
	prm.Param("status", tmpl.Bind("status"))
	prm.Param("hash", tmpl.Bind("hash"))
	tmpl.MustResolve(root)
	return tmpl
}

/*
	Metadata Doc Operations
*/

func CreateFileDoc(ctx context.Context, bulker bulk.Bulk, doc []byte, source string, fileID string) (string, error) {
	span, ctx := apm.StartSpan(ctx, "createFileInfo", "create")
	defer span.End()
	return bulker.Create(ctx, fmt.Sprintf(UploadHeaderIndexPattern, source), fileID, doc, bulk.WithRefresh())
}

func UpdateFileDoc(ctx context.Context, bulker bulk.Bulk, source string, fileID string, status file.Status, hash string) error {
	span, ctx := apm.StartSpan(ctx, "updateFileInfo", "update_by_query")
	defer span.End()
	client := bulker.Client()

	q, err := UpdateMetaDocByID.Render(map[string]interface{}{
		"_id":    fileID,
		"status": string(status),
		"hash":   hash,
		"source": "ctx._source.file.Status = params.status; if(params.hash != ''){ ctx._source.transithash = ['sha256':params.hash]; }",
	})
	if err != nil {
		return err
	}

	resp, err := client.UpdateByQuery([]string{fmt.Sprintf(UploadHeaderIndexPattern, source)}, client.UpdateByQuery.WithContext(ctx),
		func(req *esapi.UpdateByQueryRequest) {
			req.Body = bytes.NewReader(q)
		})
	if err != nil {
		return err
	}

	type ByQueryResponse struct {
		Error es.ErrorT `json:"error"`
	}

	var response ByQueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return err
	}
	zerolog.Ctx(ctx).Trace().Int("status_code", resp.StatusCode).Interface("response", response).Msg("updated file metadata document")

	if response.Error.Type != "" {
		return fmt.Errorf("%s: %s caused by %s: %s", response.Error.Type, response.Error.Reason, response.Error.Cause.Type, response.Error.Cause.Reason)
	}

	return nil
}

/*
	Chunk Operations
*/

func IndexChunk(ctx context.Context, client *elasticsearch.Client, body *cbor.ChunkEncoder, source string, fileID string, chunkNum int) error {
	span, _ := apm.StartSpan(ctx, "createChunk", "create")
	defer span.End()
	chunkDocID := fmt.Sprintf("%s.%d", fileID, chunkNum)
	resp, err := client.Create(fmt.Sprintf(UploadDataIndexPattern, source), chunkDocID, body, func(req *esapi.CreateRequest) {
		req.DocumentID = chunkDocID
		if req.Header == nil {
			req.Header = make(http.Header)
		}
		req.Header.Set("Content-Type", "application/cbor")
		req.Header.Set("Accept", "application/json")
	})
	if err != nil {
		return err
	}

	var response ChunkUploadResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return err
	}
	zerolog.Ctx(ctx).Trace().Int("status_code", resp.StatusCode).Interface("chunk-response", response).Msg("uploaded chunk")

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
	span, ctx := apm.StartSpan(ctx, "deleteChunk", "delete_by_query")
	defer span.End()
	q, err := MatchChunkByDocument.Render(map[string]interface{}{
		"_id": fmt.Sprintf("%s.%d", fileID, chunkNum),
	})
	if err != nil {
		return err
	}
	client := bulker.Client()
	_, err = client.DeleteByQuery([]string{fmt.Sprintf(UploadDataIndexPattern, source)}, bytes.NewReader(q), client.DeleteByQuery.WithContext(ctx))
	return err
}

func DeleteAllChunksForFile(ctx context.Context, bulker bulk.Bulk, source string, baseID string) error {
	q, err := MatchChunkByBID.Render(map[string]interface{}{
		file.FieldBaseID: baseID,
	})
	if err != nil {
		return err
	}
	client := bulker.Client()
	_, err = client.DeleteByQuery([]string{fmt.Sprintf(UploadDataIndexPattern, source)}, bytes.NewReader(q), client.DeleteByQuery.WithContext(ctx))
	return err
}

func EnsureChunksIndexed(ctx context.Context, client *elasticsearch.Client, source string) error {
	req := esapi.IndicesRefreshRequest{
		Index: []string{fmt.Sprintf(UploadDataIndexPattern, source)},
	}
	resp, err := req.Do(ctx, client)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		zerolog.Ctx(ctx).Warn().Int("status_code", resp.StatusCode).Msg("File Chunk Index refresh gave abnormal response")
	}
	return err
}
