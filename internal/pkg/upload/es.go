// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upload

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dsl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/upload/cbor"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/rs/zerolog/log"
)

const (
	// integration name is substituted in
	FileHeaderIndexPattern = ".fleet-files-%s"
	FileDataIndexPattern   = ".fleet-file-data-%s"

	FieldBaseID   = "bid"
	FieldLast     = "last"
	FieldSHA2     = "sha2"
	FieldUploadID = "upload_id"
)

var (
	QueryChunkIDs   = prepareFindChunkIDs()
	QueryUploadID   = prepareFindMetaByUploadID()
	QueryChunkInfo  = prepareChunkWithoutData()
	MatchChunkByBID = prepareQueryChunkByBID()
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

// get fields other than the byte payload (data)
func prepareChunkWithoutData() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()
	root := dsl.NewRoot()
	root.Param("_source", false)
	root.Query().Term(FieldBaseID, tmpl.Bind(FieldBaseID), nil)
	root.Param("fields", []string{FieldSHA2, FieldLast, FieldBaseID})
	root.Param("script_fields", map[string]interface{}{
		"size": map[string]interface{}{
			"script": map[string]interface{}{
				"lang":   "painless",
				"source": "params._source.data.length",
			},
		},
	})
	root.Size(10000)
	tmpl.MustResolve(root)
	return tmpl
}

func prepareFindMetaByUploadID() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()
	root := dsl.NewRoot()
	//root.Param("_source", false) // do not return large data payload
	root.Query().Term(FieldUploadID, tmpl.Bind(FieldUploadID), nil)
	tmpl.MustResolve(root)
	return tmpl
}

func prepareQueryChunkByBID() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()
	root := dsl.NewRoot()
	root.Query().Term(FieldBaseID, tmpl.Bind(FieldBaseID), nil)
	tmpl.MustResolve(root)
	return tmpl
}

/*
	Metadata Doc Operations
*/

func CreateFileDoc(ctx context.Context, bulker bulk.Bulk, doc []byte, source string, fileID string) (string, error) {
	return bulker.Create(ctx, fmt.Sprintf(FileHeaderIndexPattern, source), fileID, doc, bulk.WithRefresh())
}

func GetFileDoc(ctx context.Context, bulker bulk.Bulk, uploadID string) ([]es.HitT, error) {

	query, err := QueryUploadID.Render(map[string]interface{}{
		FieldUploadID: uploadID,
	})
	if err != nil {
		return nil, err
	}

	res, err := bulker.Search(ctx, fmt.Sprintf(FileHeaderIndexPattern, "*"), query)
	if err != nil {
		return nil, err
	}

	return res.HitsT.Hits, nil
}

func UpdateFileDoc(ctx context.Context, bulker bulk.Bulk, source string, fileID string, data []byte) error {
	return bulker.Update(ctx, fmt.Sprintf(FileHeaderIndexPattern, source), fileID, data)
}

/*
	Chunk Operations
*/

func IndexChunk(ctx context.Context, client *elasticsearch.Client, body *cbor.ChunkEncoder, source string, docID string, chunkNum int) error {
	resp, err := client.Index(fmt.Sprintf(FileDataIndexPattern, source), body, func(req *esapi.IndexRequest) {
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

// Retrieves a subset of chunk document fields, specifically omitting the Data payload (bytes)
// but adding the calculated field "size", that is the length, in bytes, of the Data field
// the chunk's ordered index position (Pos) is also parsed from the document ID
func GetChunkInfos(ctx context.Context, bulker bulk.Bulk, baseID string) ([]ChunkInfo, error) {
	query, err := QueryChunkInfo.Render(map[string]interface{}{
		FieldBaseID: baseID,
	})
	if err != nil {
		return nil, err
	}

	res, err := bulker.Search(ctx, fmt.Sprintf(FileDataIndexPattern, "*"), query)
	if err != nil {
		return nil, err
	}

	chunks := make([]ChunkInfo, len(res.HitsT.Hits))

	var (
		bid  string
		last bool
		sha2 string
		size int
		ok   bool
	)

	for i, h := range res.HitsT.Hits {
		if bid, ok = getResultsFieldString(h.Fields, FieldBaseID); !ok {
			return nil, fmt.Errorf("unable to retrieve %s field from chunk document", FieldBaseID)
		}
		if last, ok = getResultsFieldBool(h.Fields, FieldLast); !ok {
			return nil, fmt.Errorf("unable to retrieve %s field from chunk document", FieldLast)
		}
		if sha2, ok = getResultsFieldString(h.Fields, FieldSHA2); !ok {
			return nil, fmt.Errorf("unable to retrieve %s field from chunk document", FieldSHA2)
		}
		if size, ok = getResultsFieldInt(h.Fields, "size"); !ok {
			return nil, errors.New("unable to retrieve size from chunk document")
		}

		chunkid := strings.TrimPrefix(h.ID, bid+".")
		chunkNum, err := strconv.Atoi(chunkid)
		if err != nil {
			return nil, fmt.Errorf("unable to parse chunk number from id %s: %w", h.ID, err)
		}
		chunks[i] = ChunkInfo{
			Pos:  chunkNum,
			BID:  bid,
			Last: last,
			SHA2: sha2,
			Size: size,
		}
	}

	return chunks, nil
}

// retrieves a full chunk document, Data included
func GetChunk(ctx context.Context, bulker bulk.Bulk, source string, fileID string, chunkNum int) (model.FileChunk, error) {
	var chunk model.FileChunk
	out, err := bulker.Read(ctx, fmt.Sprintf(FileDataIndexPattern, source), fmt.Sprintf("%s.%d", fileID, chunkNum))
	if err != nil {
		return chunk, err
	}
	err = json.Unmarshal(out, &chunk)
	return chunk, err
}

func DeleteChunk(ctx context.Context, bulker bulk.Bulk, source string, fileID string, chunkNum int) error {
	return bulker.Delete(ctx, fmt.Sprintf(FileDataIndexPattern, source), fmt.Sprintf("%s.%d", fileID, chunkNum))
}

func DeleteChunksByQuery(ctx context.Context, bulker bulk.Bulk, source string, baseID string) error {
	q, err := MatchChunkByBID.Render(map[string]interface{}{
		FieldBaseID: baseID,
	})
	if err != nil {
		return err
	}
	_, err = bulker.Client().DeleteByQuery([]string{fmt.Sprintf(FileDataIndexPattern, source)}, bytes.NewReader(q))
	return err
}

// convenience function for translating the elasticsearch "field" response format
// of "field": { "a": [value], "b": [value] }
func getResultField(fields map[string]interface{}, key string) (interface{}, bool) {
	array, ok := fields[key].([]interface{})
	if !ok {
		return nil, false
	}
	if array == nil || len(array) < 1 {
		return nil, false
	}
	return array[0], true
}

func getResultsFieldString(fields map[string]interface{}, key string) (string, bool) {
	val, ok := getResultField(fields, key)
	if !ok {
		return "", false
	}
	str, ok := val.(string)
	return str, ok
}
func getResultsFieldBool(fields map[string]interface{}, key string) (bool, bool) {
	val, ok := getResultField(fields, key)
	if !ok {
		return false, false
	}
	b, ok := val.(bool)
	return b, ok
}
func getResultsFieldInt(fields map[string]interface{}, key string) (int, bool) {
	val, ok := getResultField(fields, key)
	if !ok {
		return 0, false
	}
	switch n := val.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	default:
		return 0, false
	}
}
