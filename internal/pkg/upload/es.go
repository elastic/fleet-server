// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upload

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dsl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/upload/cbor"
	"github.com/elastic/go-elasticsearch/v7"
	"github.com/elastic/go-elasticsearch/v7/esapi"
	"github.com/rs/zerolog/log"
)

const (
	// integration name is substituted in
	FileHeaderIndexPattern = ".fleet-files-%s"
	FileDataIndexPattern   = ".fleet-file-data-%s"

	FieldBaseID = "bid"
)

var (
	QueryChunkIDs = prepareFindChunkIDs()
)

func prepareFindChunkIDs() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()
	root := dsl.NewRoot()
	root.Param("_source", false) // do not return large data payload
	root.Query().Term(FieldBaseID, tmpl.Bind(FieldBaseID), nil)
	root.Size(10000) // 10k elasticsearch maximum. Result count breaks above 42gb files
	tmpl.MustResolve(root)
	return tmpl
}

func CreateFileDoc(ctx context.Context, bulker bulk.Bulk, doc []byte, source string, fileID string) (string, error) {
	return bulker.Create(ctx, fmt.Sprintf(FileHeaderIndexPattern, source), fileID, doc, bulk.WithRefresh())
}

func UpdateFileDoc(ctx context.Context, bulker bulk.Bulk, source string, fileID string, data []byte) error {
	return bulker.Update(ctx, fmt.Sprintf(FileHeaderIndexPattern, source), fileID, data)
}

func IndexChunk(ctx context.Context, client *elasticsearch.Client, body *cbor.ChunkEncoder, source string, docID string, chunkID int) error {

	/*
		// the non-streaming version
		buf := bytes.NewBuffer(nil)
		out, err := io.ReadAll(data)
		if err != nil {
			return err
		}
		data.Close()
		err = cbor.NewEncoder(buf).Encode(map[string]interface{}{
			"bid":  fileID,
			"last": false,
			"data": out,
		})
		if err != nil {
			return err
		}
		buf2 := buf.Bytes()
	*/

	req := esapi.IndexRequest{
		Index:      fmt.Sprintf(FileDataIndexPattern, source),
		Body:       body,
		DocumentID: fmt.Sprintf("%s.%d", docID, chunkID),
		Refresh:    "true",
	}
	// need to set the Content-Type of the request to CBOR, notes below
	overrider := contentTypeOverrider{client}
	resp, err := req.Do(ctx, overrider)
	/*
		standard approach when content-type override no longer needed

		resp, err := client.Index(".fleet-file_data", data, func(req *esapi.IndexRequest) {
			req.DocumentID = fmt.Sprintf("%s.%d", fileID, chunkID)
			if req.Header == nil {
				req.Header = make(http.Header)
			}
			// the below setting actually gets overridden in the ES client
			// when it checks for the existence of r.Body, and then sets content-type to JSON
			// this setting is then *added* so multiple content-types are sent.
			// https://github.com/elastic/go-elasticsearch/blob/7.17/esapi/api.index.go#L183-L193
			// we have to temporarily override this with a custom esapi.Transport
			req.Header.Set("Content-Type", "application/cbor")
			req.Header.Set("Accept","application/json") // this one has no issues being set this way. We need to specify we want JSON response
		})*/
	if err != nil {
		return err
	}

	var response ChunkUploadResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return err
	}
	log.Trace().Int("statuscode", resp.StatusCode).Interface("chunk-response", response).Msg("uploaded chunk")

	if response.Error.Type != "" {
		return fmt.Errorf("%s: %s. Caused by %s: %s", response.Error.Type, response.Error.Reason, response.Error.Cause.Type, response.Error.Cause.Reason)
	}
	return nil
}

type contentTypeOverrider struct {
	client *elasticsearch.Client
}

func (c contentTypeOverrider) Perform(req *http.Request) (*http.Response, error) {
	req.Header.Set("Content-Type", "application/cbor") // we will SEND cbor
	req.Header.Set("Accept", "application/json")       // but we want JSON back
	return c.client.Perform(req)
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
	Error struct {
		Type   string `json:"type"`
		Reason string `json:"reason"`
		Cause  struct {
			Type   string `json:"type"`
			Reason string `json:"reason"`
		} `json:"caused_by"`
	} `json:"error"`
}

func ListChunkIDs(ctx context.Context, bulker bulk.Bulk, source string, fileID string) ([]es.HitT, error) {
	return listChunkIDs(ctx, bulker, fmt.Sprintf(FileDataIndexPattern, source), fileID)
}

func listChunkIDs(ctx context.Context, bulker bulk.Bulk, index string, fileID string) ([]es.HitT, error) {
	query, err := QueryChunkIDs.Render(map[string]interface{}{
		FieldBaseID: fileID,
	})
	if err != nil {
		return nil, err
	}

	res, err := bulker.Search(ctx, index, query)
	if err != nil {
		return nil, err
	}
	return res.HitsT.Hits, nil
}

func GetChunk(ctx context.Context, bulker bulk.Bulk, source string, fileID string, chunkID int) (model.FileChunk, error) {
	var chunk model.FileChunk
	out, err := bulker.Read(ctx, fmt.Sprintf(FileDataIndexPattern, source), fmt.Sprintf("%s.%d", fileID, chunkID))
	if err != nil {
		return chunk, err
	}
	err = json.Unmarshal(out, &chunk)
	return chunk, err
}
