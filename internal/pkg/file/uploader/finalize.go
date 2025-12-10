// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package uploader

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"

	"github.com/rs/zerolog"
	"go.elastic.co/apm/v2"

	"github.com/elastic/fleet-server/v7/internal/pkg/file"
)

var (
	ErrFailValidation  = errors.New("file contents failed validation")
	ErrStatusNoUploads = errors.New("file closed, not accepting uploads")
)

func (u *Uploader) Complete(ctx context.Context, id string, transitHash string) (file.Info, error) {
	span, ctx := apm.StartSpan(ctx, "completeUpload", "process")
	defer span.End()
	// make sure document is freshly fetched, not cached
	// so accurate status checking happens
	info, err := file.GetInfo(ctx, u.bulker, UploadHeaderIndexPattern, id)
	if err != nil {
		return info, err
	}

	/*
		Verify Upload
	*/

	// if already done, failed or deleted, exit
	if !info.StatusCanUpload() {
		return info, ErrStatusNoUploads
	}

	// complete may be called before most recent chunks are available for search yet
	// this explicitly calls refresh once at the end, instead of refreshing on each chunk
	if err := EnsureChunksIndexed(ctx, u.bulker.Client(), info.Source); err != nil {
		return info, err
	}

	chunks, err := file.GetChunkInfos(ctx, u.bulker, UploadDataIndexPattern, info.DocID, file.GetChunkInfoOpt{IncludeSize: true, RequireHash: true})
	if err != nil {
		return info, err
	}
	vSpan, _ := apm.StartSpan(ctx, "validateUpload", "validate")
	if !u.allChunksPresent(ctx, info, chunks) {
		vSpan.End()
		return info, ErrMissingChunks
	}
	if !u.verifyChunkInfo(ctx, info, chunks, transitHash) {
		if err := SetStatus(ctx, u.bulker, info, file.StatusFail); err != nil {
			zerolog.Ctx(ctx).Warn().Err(err).Str("fileID", info.DocID).Str("uploadID", info.ID).Msg("file upload failed chunk validation, but encountered an error setting the upload status to failure")
		}
		if err := DeleteAllChunksForFile(ctx, u.bulker, info.Source, info.DocID); err != nil {
			zerolog.Ctx(ctx).Warn().Err(err).Str("fileID", info.DocID).Str("uploadID", info.ID).Msg("file upload failed chunk validation, but encountered an error deleting left-behind chunk data")
		}
		vSpan.End()
		return info, ErrFailValidation
	}
	vSpan.End()

	/*
		Upload OK. Update status and save valid transithash
	*/
	if err := MarkComplete(ctx, u.bulker, info, transitHash); err != nil {
		return info, err

	}

	return info, nil
}

func (u *Uploader) allChunksPresent(ctx context.Context, info file.Info, chunks []file.ChunkInfo) bool {
	log := zerolog.Ctx(ctx)
	// check overall count
	if len(chunks) != info.Count {
		log.Warn().Int("expectedCount", info.Count).Int("received", len(chunks)).Interface("chunks", chunks).Msg("mismatch number of chunks")
		return false
	}

	// now ensure all positions are accounted for, no gaps, etc
	sort.Slice(chunks, func(i, j int) bool {
		return chunks[i].Pos < chunks[j].Pos
	})

	for i, c := range chunks {
		if c.Pos != i {
			log.Warn().Int("expected", i).Interface("chunk", c).Msg("chunk position doesn't match. May be a gap in uploaded file")
			return false
		}
	}

	return true
}

func (u *Uploader) verifyChunkInfo(ctx context.Context, info file.Info, chunks []file.ChunkInfo, transitHash string) bool {
	log := zerolog.Ctx(ctx)
	// verify all chunks except last are info.ChunkSize size
	// verify last: false (or field excluded) for all except final chunk
	// verify final chunk is last: true
	// verify hash

	hasher := sha256.New()

	for i, chunk := range chunks {
		if i < info.Count-1 {
			// all chunks except last must have last:false
			// and be PRECISELY info.ChunkSize bytes long
			if chunk.Last {
				log.Debug().Int("chunkID", i).Msg("non-final chunk was incorrectly marked last")
				return false
			}
			if chunk.Size != int(info.ChunkSize) {
				log.Debug().Int64("requiredSize", info.ChunkSize).Int("chunkID", i).Int("gotSize", chunk.Size).Msg("chunk was undersized")
				return false
			}
		} else {
			// last chunk must be marked last:true
			// and can be any valid size (0,ChunkSize]
			if !chunk.Last {
				log.Debug().Int("chunkID", i).Msg("final chunk was not marked as final")
				return false
			}
			if chunk.Size == 0 {
				log.Debug().Int("chunkID", i).Msg("final chunk was 0 size")
				return false
			}
			if chunk.Size > int(info.ChunkSize) {
				log.Debug().Int("chunk-size", chunk.Size).Int("maxsize", int(info.ChunkSize)).Msg("final chunk was oversized")
				return false
			}
		}

		// write the byte-decoded hash for this chunk to the
		// running hash for the entire file (transithash)
		rawHash, err := hex.DecodeString(chunk.SHA2)
		if err != nil {
			log.Warn().Err(err).Msg("error decoding chunk hash")
			return false
		}
		if n, err := hasher.Write(rawHash); err != nil {
			log.Error().Err(err).Msg("error computing transitHash from component chunk hashes")
			return false
		} else if n != len(rawHash) {
			log.Error().Int("wrote", n).Int("expected", len(rawHash)).Msg("transitHash calculation failure, could not write to hasher")
			return false
		}
	}

	calcHash := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(transitHash, calcHash) {
		log.Warn().Str("provided-hash", transitHash).Str("calc-hash", calcHash).Msg("file upload streaming hash does not match")
		return false
	}

	return true
}
