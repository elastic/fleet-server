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

	"github.com/rs/zerolog"
	"go.elastic.co/apm/v2"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/file"
	"github.com/elastic/fleet-server/v7/internal/pkg/file/cbor"
	"github.com/elastic/fleet-server/v7/internal/pkg/file/uploader"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/go-elasticsearch/v8"
)

const (
	maxUploadTimer = 24 * time.Hour
)

var (
	ErrTransitHashRequired = errors.New("transit hash required")

	ErrAgentIDMissing       = errors.New("required field agent_id is missing")
	ErrFileInfoBodyRequired = fmt.Errorf("file info body is required")
)

// FIXME Should we use the structs in openapi.gen.go instead of the generic ones? Will need to rework the uploader if we do
type UploadT struct {
	cfg         *config.Server
	bulker      bulk.Bulk
	chunkClient *elasticsearch.Client
	cache       cache.Cache
	uploader    *uploader.Uploader
	authAgent   func(*http.Request, *string, bulk.Bulk, cache.Cache) (*model.Agent, error) // injectable for testing purposes
	authAPIKey  func(*http.Request, bulk.Bulk, cache.Cache) (*apikey.APIKey, error)        // as above
}

func NewUploadT(cfg *config.Server, bulker bulk.Bulk, chunkClient *elasticsearch.Client, cache cache.Cache) *UploadT {
	return &UploadT{
		cfg:         cfg,
		chunkClient: chunkClient,
		bulker:      bulker,
		cache:       cache,
		uploader:    uploader.New(chunkClient, bulker, cache, cfg.Limits.MaxFileStorageByteSize, maxUploadTimer),
		authAgent:   authAgent,
		authAPIKey:  authAPIKey,
	}
}

func (ut *UploadT) validateUploadBeginRequest(ctx context.Context, reader io.Reader) (uploader.JSDict, string, error) {
	span, _ := apm.StartSpan(ctx, "validateRequest", "validate")
	defer span.End()

	payload, err := uploader.ReadDict(reader)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, "", fmt.Errorf("%w: %w", ErrFileInfoBodyRequired, err)
		}

		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return nil, "", fmt.Errorf("payload is too large: %w", err)
		}
		return nil, "", &BadRequestErr{msg: "unable to decode upload begin request", nextErr: err}
	}

	// check API key matches payload agent ID
	agentID, ok := payload.Str("agent_id")
	if !ok || agentID == "" {
		return nil, "", ErrAgentIDMissing
	}
	return payload, agentID, nil
}

func (ut *UploadT) handleUploadBegin(_ zerolog.Logger, w http.ResponseWriter, r *http.Request) error {
	// ensure body is not excessively large to prevent memory exhaustion DoS attach
	if ut.cfg.Limits.UploadStartLimit.MaxBody > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, ut.cfg.Limits.UploadStartLimit.MaxBody)
	}

	// decode early to match agentID in the payload
	payload, agentID, err := ut.validateUploadBeginRequest(r.Context(), r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return err
		}

		return err
	}

	agent, err := ut.authAgent(r, &agentID, ut.bulker, ut.cache)
	if err != nil {
		return err
	}

	// validate payload, enrich with additional fields, and write metadata doc to ES
	info, err := ut.uploader.Begin(r.Context(), agent.Namespaces, payload)
	if err != nil {
		return err
	}

	span, _ := apm.StartSpan(r.Context(), "response", "write")
	defer span.End()

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
	if err := uploader.IndexChunk(r.Context(), ut.chunkClient, ce, upinfo.Source, chunkInfo.BID, chunkInfo.Pos); err != nil {
		return err
	}

	span, ctx := apm.StartSpan(r.Context(), "validateIndexChunk", "validate")
	hashsum := hex.EncodeToString(hash.Sum(nil))

	if !strings.EqualFold(chunkHash, hashsum) {
		// delete document, since we wrote it, but the hash was invalid
		// context scoped to allow this operation to finish even if client disconnects
		if err := uploader.DeleteChunk(ctx, ut.bulker, upinfo.Source, chunkInfo.BID, chunkInfo.Pos); err != nil {
			zlog.Warn().Err(err).
				Str("source", upinfo.Source).
				Str("fileID", chunkInfo.BID).
				Int("chunkNum", chunkInfo.Pos).
				Msg("a chunk hash mismatch occurred, and fleet server was unable to remove the invalid chunk")
		}
		span.End()
		return uploader.ErrHashMismatch
	}
	span.End()

	span, _ = apm.StartSpan(r.Context(), "response", "write")
	defer span.End()
	w.WriteHeader(http.StatusOK)
	return nil
}

func (ut *UploadT) validateUploadCompleteRequest(r *http.Request, id string) (string, error) {
	span, ctx := apm.StartSpan(r.Context(), "validateRequest", "validate")
	defer span.End()

	info, err := ut.uploader.GetUploadInfo(ctx, id)
	if err != nil {
		return "", err
	}
	// need to auth that it matches the ID in the initial
	// doc, but that means we had to doc-lookup early
	if _, err := ut.authAgent(r, &info.AgentID, ut.bulker, ut.cache); err != nil {
		return "", fmt.Errorf("error authenticating for upload finalization: %w", err)
	}

	var req UploadCompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return "", uploader.ErrPayloadSizeTooLarge
		}

		return "", &BadRequestErr{msg: "unable to decode upload complete request"}
	}

	hash := strings.TrimSpace(req.Transithash.Sha256)
	if hash == "" {
		return "", ErrTransitHashRequired
	}
	return hash, nil
}

func (ut *UploadT) handleUploadComplete(_ zerolog.Logger, w http.ResponseWriter, r *http.Request, uplID string) error {
	// ensure body is not excessively large to prevent memory exhaustion DoS attach
	if ut.cfg.Limits.UploadEndLimit.MaxBody > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, ut.cfg.Limits.UploadEndLimit.MaxBody)
	}

	hash, err := ut.validateUploadCompleteRequest(r, uplID)
	if err != nil {
		return err
	}

	_, err = ut.uploader.Complete(r.Context(), uplID, hash)
	if err != nil {
		return err
	}

	span, _ := apm.StartSpan(r.Context(), "response", "write")
	defer span.End()
	_, err = w.Write([]byte(`{"status":"ok"}`))
	if err != nil {
		return err
	}
	return nil
}
