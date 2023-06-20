// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package file

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dsl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
)

const (
	FieldBaseID   = "bid"
	FieldLast     = "last"
	FieldSHA2     = "sha2"
	FieldUploadID = "upload_id"
)

var (
	QueryChunkInfoWithSize = prepareChunkInfo(true)
	QueryChunkInfo         = prepareChunkInfo(false)
	QueryUploadID          = prepareFindMetaByUploadID()
)

// get fields other than the byte payload (data)
func prepareChunkInfo(size bool) *dsl.Tmpl {
	tmpl := dsl.NewTmpl()
	root := dsl.NewRoot()
	root.Param("_source", false)
	root.Query().Term(FieldBaseID, tmpl.Bind(FieldBaseID), nil)
	root.Param("fields", []string{FieldSHA2, FieldLast, FieldBaseID})
	if size {
		root.Param("script_fields", map[string]interface{}{
			"size": map[string]interface{}{
				"script": map[string]interface{}{
					"lang":   "painless",
					"source": "params._source.data.length",
				},
			},
		})
	}
	root.Size(10000)
	tmpl.MustResolve(root)
	return tmpl
}

func prepareFindMetaByUploadID() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()
	root := dsl.NewRoot()
	root.Query().Term(FieldUploadID, tmpl.Bind(FieldUploadID), nil)
	tmpl.MustResolve(root)
	return tmpl
}

func GetMetadata(ctx context.Context, bulker bulk.Bulk, indexPattern string, uploadID string) ([]es.HitT, error) {

	query, err := QueryUploadID.Render(map[string]interface{}{
		FieldUploadID: uploadID,
	})
	if err != nil {
		return nil, err
	}

	res, err := bulker.Search(ctx, fmt.Sprintf(indexPattern, "*"), query)
	if err != nil {
		return nil, err
	}

	return res.HitsT.Hits, nil
}

// Retrieves a file Metadata as an Info object
func GetInfo(ctx context.Context, bulker bulk.Bulk, indexPattern string, uploadID string) (Info, error) {
	results, err := GetMetadata(ctx, bulker, indexPattern, uploadID)
	if err != nil {
		return Info{}, err
	}
	if len(results) == 0 {
		return Info{}, ErrInvalidID
	}
	if len(results) > 1 {
		return Info{}, fmt.Errorf("unable to locate upload record, got %d records, expected 1", len(results))
	}

	var fi MetaDoc
	if err := json.Unmarshal(results[0].Source, &fi); err != nil {
		return Info{}, fmt.Errorf("file meta doc parsing error: %w", err)
	}

	// calculate number of chunks required
	cnt := fi.File.Size / fi.File.ChunkSize
	if fi.File.Size%fi.File.ChunkSize > 0 {
		cnt += 1
	}

	return Info{
		ID:        fi.UploadID,
		Source:    fi.Source,
		AgentID:   fi.AgentID,
		ActionID:  fi.ActionID,
		DocID:     results[0].ID,
		ChunkSize: fi.File.ChunkSize,
		Total:     fi.File.Size,
		Count:     int(cnt),
		Start:     fi.Start,
		Status:    Status(fi.File.Status),
	}, nil
}

// retrieves a full chunk document, Data included
func GetChunk(ctx context.Context, bulker bulk.Bulk, indexPattern string, source string, fileID string, chunkNum int) (Chunk, error) {
	var chunk Chunk
	out, err := bulker.Read(ctx, fmt.Sprintf(indexPattern, source), fmt.Sprintf("%s.%d", fileID, chunkNum))
	if err != nil {
		return chunk, err
	}
	err = json.Unmarshal(out, &chunk)
	return chunk, err
}

type GetChunkInfoOpt struct {
	IncludeSize bool
	RequireHash bool
}

// Retrieves a subset of chunk document fields, specifically omitting the Data payload (bytes)
// the chunk's ordered index position (Pos) is also parsed from the document ID.
// Optionally adding the calculated field "size", that is the length, in bytes, of the Data field.
// and optionally validating that a hash field is present
func GetChunkInfos(ctx context.Context, bulker bulk.Bulk, indexPattern string, baseID string, opt GetChunkInfoOpt) ([]ChunkInfo, error) {
	tpl := QueryChunkInfo
	if opt.IncludeSize {
		tpl = QueryChunkInfoWithSize
	}
	query, err := tpl.Render(map[string]interface{}{
		FieldBaseID: baseID,
	})
	if err != nil {
		return nil, err
	}

	res, err := bulker.Search(ctx, fmt.Sprintf(indexPattern, "*"), query)
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
			// Files written by Kibana omit this field for all intermediate chunks
			// and only write last:true on final chunk. False by default
			last = false
		}
		if sha2, ok = getResultsFieldString(h.Fields, FieldSHA2); opt.RequireHash && !ok {
			return nil, fmt.Errorf("unable to retrieve %s field from chunk document", FieldSHA2)
		}
		if size, ok = getResultsFieldInt(h.Fields, "size"); opt.IncludeSize && !ok {
			return nil, errors.New("unable to retrieve size from chunk document")
		}
		chunkid := strings.TrimPrefix(h.ID, bid+".")
		chunkNum, err := strconv.Atoi(chunkid)
		if err != nil {
			return nil, fmt.Errorf("unable to parse chunk number from id %s: %w", h.ID, err)
		}
		chunks[i] = ChunkInfo{
			Pos:   chunkNum,
			BID:   bid,
			Last:  last,
			SHA2:  sha2,
			Size:  size,
			Index: h.Index,
			ID:    h.ID,
		}
	}

	return chunks, nil
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
