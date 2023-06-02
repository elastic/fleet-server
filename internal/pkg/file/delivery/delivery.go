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
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/file"
	"github.com/elastic/fleet-server/v7/internal/pkg/file/cbor"
	"github.com/elastic/go-elasticsearch/v8"
)

type Deliverer struct {
	sizeLimit int64
	timeLimit time.Duration

	client *elasticsearch.Client
	bulker bulk.Bulk
}

func New(client *elasticsearch.Client, bulker bulk.Bulk, sizeLimit int64) *Deliverer {
	return &Deliverer{
		client:    client,
		bulker:    bulker,
		sizeLimit: sizeLimit,
	}
}

func (d *Deliverer) FindFileForAgent(ctx context.Context, fileID string, agentID string) (file.MetaDoc, error) {
	result, err := findFileForAgent(ctx, d.bulker, fileID, agentID)
	if err != nil {
		return file.MetaDoc{}, err
	}
	if result == nil || len(result.Hits) == 0 {
		return file.MetaDoc{}, file.ErrInvalidID
	}

	var fi file.MetaDoc
	if err := json.Unmarshal(result.Hits[0].Source, &fi); err != nil {
		return file.MetaDoc{}, fmt.Errorf("file meta doc parsing error: %w", err)
	}

	return fi, nil
}

func (d *Deliverer) SendFile(ctx context.Context, w io.Writer, f file.MetaDoc, fileID string) error {

	// find chunk indices behind alias, doc IDs
	infos, err := file.GetChunkInfos(ctx, d.bulker, FileDataIndexPattern, fileID, file.GetChunkInfoOpt{})
	if err != nil {
		return err
	}

	for _, chunkInfo := range infos {
		body, err := readChunkStream(d.client, chunkInfo.Index, chunkInfo.ID)
		if err != nil {
			body.Close()
			return err
		}

		chunk, err := cbor.NewChunkDecoder(body).Decode()
		body.Close()
		if err != nil {
			return err
		}

		n, err := w.Write(chunk)
		if err != nil {
			return err
		}
		if n != len(chunk) {
			return errors.New("chunk could not be written")
		}
	}

	return nil
}
