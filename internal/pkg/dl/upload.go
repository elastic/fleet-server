// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/upload"
	"github.com/elastic/go-elasticsearch/v7"
	"github.com/elastic/go-elasticsearch/v7/esapi"
	"github.com/rs/zerolog/log"
)

const (
	// @todo: neither of these should be static. But should be specific to an integration
	// somewhat configurable, but need to follow a pattern so that Fleet Server has write access
	FileHeaderIndex = ".fleet-files"
	FileDataIndex   = ".fleet-file_data"
)

func CreateUploadInfo(ctx context.Context, bulker bulk.Bulk, fi model.FileInfo, fileID string) (string, error) {
	return createUploadInfo(ctx, bulker, FileHeaderIndex, fi, fileID) // @todo: index destination is an input (and different per integration)
}

func createUploadInfo(ctx context.Context, bulker bulk.Bulk, index string, fi model.FileInfo, fileID string) (string, error) {
	body, err := json.Marshal(fi)
	if err != nil {
		return "", err
	}
	return bulker.Create(ctx, index, fileID, body, bulk.WithRefresh())
}

func UpdateUpload(ctx context.Context, bulker bulk.Bulk, fileID string, data []byte) error {
	return updateUpload(ctx, bulker, FileHeaderIndex, fileID, data)
}

func updateUpload(ctx context.Context, bulker bulk.Bulk, index string, fileID string, data []byte) error {
	return bulker.Update(ctx, index, fileID, data)
}

func UploadChunk(ctx context.Context, client *elasticsearch.Client, data io.ReadCloser, chunkInfo upload.ChunkInfo) error {
	cbor := upload.NewCBORChunkWriter(data, chunkInfo.Final, chunkInfo.Upload.ID, chunkInfo.Upload.ChunkSize)

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
		Index:      FileDataIndex,
		Body:       cbor,
		DocumentID: fmt.Sprintf("%s.%d", chunkInfo.Upload.ID, chunkInfo.ID),
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
