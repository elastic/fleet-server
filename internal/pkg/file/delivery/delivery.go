// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package delivery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/file"
	"github.com/elastic/fleet-server/v7/internal/pkg/file/cbor"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/rs/zerolog"
	"go.elastic.co/apm/v2"
)

var (
	ErrNoFile = errors.New("file data not found")
)

type Deliverer struct {
	sizeLimit *uint64

	client *elasticsearch.Client
	bulker bulk.Bulk
}

func New(client *elasticsearch.Client, bulker bulk.Bulk, sizeLimit *uint64) *Deliverer {
	return &Deliverer{
		client:    client,
		bulker:    bulker,
		sizeLimit: sizeLimit,
	}
}

func (d *Deliverer) FindFileForAgent(ctx context.Context, fileID string, agentID string) (file.MetaDoc, error) {
	span, ctx := apm.StartSpan(ctx, "findFile", "process")
	defer span.End()
	result, err := findFileForAgent(ctx, d.bulker, fileID, agentID)
	if err != nil {
		return file.MetaDoc{}, err
	}
	if result == nil || len(result.Hits) == 0 {
		return file.MetaDoc{}, ErrNoFile
	}

	var fi file.MetaDoc
	if err := json.Unmarshal(result.Hits[0].Source, &fi); err != nil {
		return file.MetaDoc{}, fmt.Errorf("file meta doc parsing error: %w", err)
	}

	return fi, nil
}

func (d *Deliverer) LocateChunks(ctx context.Context, zlog zerolog.Logger, fileID string) ([]file.ChunkInfo, error) {
	// find chunk indices behind alias, doc IDs
	infos, err := file.GetChunkInfos(ctx, d.bulker, FileDataIndexPattern, fileID, file.GetChunkInfoOpt{})
	if err != nil {
		zlog.Error().Err(err).Msg("problem getting infos")
		return nil, err
	}

	if len(infos) == 0 {
		zlog.Warn().Str("fileID", fileID).Msg("chunk documents not found for file")
		return nil, ErrNoFile
	}
	zlog.Trace().Int("number of chunks found", len(infos)).Msg("chunks found")

	return infos, nil
}

func (d *Deliverer) SendFile(ctx context.Context, zlog zerolog.Logger, w io.Writer, chunks []file.ChunkInfo, fileID string) error {
	span, ctx := apm.StartSpan(ctx, "response", "write")
	defer span.End()
	sort.SliceStable(chunks, func(i, j int) bool {
		return chunks[i].Pos < chunks[j].Pos
	})
	for _, chunkInfo := range chunks {
		body, err := readChunkStream(ctx, d.client, chunkInfo.Index, chunkInfo.ID)
		if err != nil {
			zlog.Error().Err(err).Str("fileID", fileID).Str("chunkID", chunkInfo.ID).Msg("error reading chunk stream")
			body.Close()
			return err
		}

		chunk, err := cbor.NewChunkDecoder(body).Decode()
		body.Close()
		if err != nil {
			zlog.Error().Err(err).Str("fileID", fileID).Str("chunkID", chunkInfo.ID).Msg("error decoding chunk")
			return err
		}

		n, err := w.Write(chunk)
		if err != nil {
			zlog.Error().Err(err).Str("fileID", fileID).Str("chunkID", chunkInfo.ID).Msg("error writing chunk to output")
			return err
		}
		if n != len(chunk) {
			zlog.Error().Err(err).Str("fileID", fileID).Str("chunkID", chunkInfo.ID).Int("expected length", n).Int("wrote length", len(chunk)).Msg("error decoding chunk")
			return errors.New("chunk could not be written")
		}
	}

	return nil
}
