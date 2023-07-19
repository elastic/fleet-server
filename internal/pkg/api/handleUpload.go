// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/file"
	"github.com/elastic/fleet-server/v7/internal/pkg/file/cbor"
	"github.com/elastic/fleet-server/v7/internal/pkg/file/uploader"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	// TODO: move to a config
	maxFileSize    = 104857600 // 100 MiB
	maxUploadTimer = 24 * time.Hour
)

var (
	ErrTransitHashRequired = errors.New("transit hash required")

	ErrAgentIDMissing       = errors.New("required field agent_id is missing")
	ErrFileInfoBodyRequired = fmt.Errorf("file info body is required")
)

// FIXME Should we use the structs in openapi.gen.go instead of the generic ones? Will need to rework the uploader if we do
type UploadT struct {
	bulker       bulk.Bulk
	chunkClient  *elasticsearch.Client
	cache        cache.Cache
	uploader     *uploader.Uploader
	authAgent    func(*http.Request, *string, bulk.Bulk, cache.Cache) (*model.Agent, error) // injectable for testing purposes
	authAPIKey   func(*http.Request, bulk.Bulk, cache.Cache) (*apikey.APIKey, error)        // as above
	refreshParam string
}

func NewUploadT(cfg *config.Server, bulker bulk.Bulk, chunkClient *elasticsearch.Client, cache cache.Cache) *UploadT {
	log.Info().
		Interface("limits", cfg.Limits.ArtifactLimit).
		Int64("maxFileSize", maxFileSize).
		Msg("upload limits")

	return &UploadT{
		chunkClient:  chunkClient,
		bulker:       bulker,
		cache:        cache,
		uploader:     uploader.New(chunkClient, bulker, cache, maxFileSize, maxUploadTimer),
		authAgent:    authAgent,
		authAPIKey:   authAPIKey,
		refreshParam: string(cfg.Bulk.Refresh),
	}
}

func (ut *UploadT) handleUploadBegin(_ zerolog.Logger, w http.ResponseWriter, r *http.Request) error {
	// decode early to match agentID in the payload
	payload, err := uploader.ReadDict(r.Body)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%w: %w", ErrFileInfoBodyRequired, err)
		}
		return err
	}

	// check API key matches payload agent ID
	agentID, ok := payload.Str("agent_id")
	if !ok || agentID == "" {
		return ErrAgentIDMissing
	}
	_, err = ut.authAgent(r, &agentID, ut.bulker, ut.cache)
	if err != nil {
		return err
	}

	// validate payload, enrich with additional fields, and write metadata doc to ES
	info, err := ut.uploader.Begin(r.Context(), payload)
	if err != nil {
		return err
	}

	// prepare and write response
	resp := UploadBeginAPIResponse{
		ChunkSize: info.ChunkSize,
		UploadId:  info.ID,
	}
	out, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(out)
	if err != nil {
		return err
	}
	return nil
}

func (ut *UploadT) handleUploadChunk(zlog zerolog.Logger, w http.ResponseWriter, r *http.Request, uplID string, chunkID int, chunkHash string) error {
	// chunkHash is checked by router
	upinfo, chunkInfo, err := ut.uploader.Chunk(r.Context(), uplID, chunkID, chunkHash)
	if err != nil {
		return err
	}

	// prevent over-sized chunks
	data := http.MaxBytesReader(w, r.Body, file.MaxChunkSize)

	// compute hash as we stream it
	hash := sha256.New()
	copier := io.TeeReader(data, hash)

	ce := cbor.NewChunkWriter(copier, chunkInfo.Last, chunkInfo.BID, chunkInfo.SHA2, upinfo.ChunkSize)
	if err := uploader.IndexChunk(r.Context(), ut.chunkClient, ce, upinfo.Source, chunkInfo.BID, chunkInfo.Pos, ut.refreshParam); err != nil {
		return err
	}

	hashsum := hex.EncodeToString(hash.Sum(nil))

	if !strings.EqualFold(chunkHash, hashsum) {
		// delete document, since we wrote it, but the hash was invalid
		// context scoped to allow this operation to finish even if client disconnects
		if err := uploader.DeleteChunk(context.Background(), ut.bulker, upinfo.Source, chunkInfo.BID, chunkInfo.Pos); err != nil {
			zlog.Warn().Err(err).
				Str("source", upinfo.Source).
				Str("fileID", chunkInfo.BID).
				Int("chunkNum", chunkInfo.Pos).
				Msg("a chunk hash mismatch occurred, and fleet server was unable to remove the invalid chunk")
		}
		return uploader.ErrHashMismatch
	}

	w.WriteHeader(http.StatusOK)
	return nil
}

func (ut *UploadT) handleUploadComplete(_ zerolog.Logger, w http.ResponseWriter, r *http.Request, uplID string) error {
	info, err := ut.uploader.GetUploadInfo(r.Context(), uplID)
	if err != nil {
		return err
	}
	// need to auth that it matches the ID in the initial
	// doc, but that means we had to doc-lookup early
	if _, err := ut.authAgent(r, &info.AgentID, ut.bulker, ut.cache); err != nil {
		return fmt.Errorf("error authenticating for upload finalization: %w", err)
	}

	var req UploadCompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return errors.New("unable to parse request body")
	}

	hash := strings.TrimSpace(req.Transithash.Sha256)
	if hash == "" {
		return ErrTransitHashRequired
	}

	info, err = ut.uploader.Complete(r.Context(), uplID, hash)
	if err != nil {
		return err
	}

	_, err = w.Write([]byte(`{"status":"ok"}`))
	if err != nil {
		return err
	}
	return nil
}
