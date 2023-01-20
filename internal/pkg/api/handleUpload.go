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
	"strconv"
	"strings"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/uploader"
	"github.com/elastic/fleet-server/v7/internal/pkg/uploader/cbor"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/julienschmidt/httprouter"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	// TODO: move to a config
	maxFileSize    = 104857600 // 100 MiB
	maxUploadTimer = 24 * time.Hour
)

func (rt Router) handleUploadStart(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	start := time.Now()
	reqID := r.Header.Get(logger.HeaderRequestID)
	zlog := log.With().
		Str(ECSHTTPRequestID, reqID).
		Logger()

	// authentication occurs inside here
	// to check that key agent ID matches the ID in the body payload yet-to-be unmarshalled
	if err := rt.ut.handleUploadStart(&zlog, w, r); err != nil {
		writeUploadError(err, w, zlog, start, "error initiating upload process")
		return
	}
}

func (rt Router) handleUploadChunk(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	start := time.Now()

	id := ps.ByName("id")
	chunkID := ps.ByName("num")

	reqID := r.Header.Get(logger.HeaderRequestID)

	zlog := log.With().
		Str(LogAgentID, id).
		Str(ECSHTTPRequestID, reqID).
		Logger()

	// simpler authentication check,  for high chunk throughput
	// since chunk checksums must match transit hash
	// AND optionally the initial hash, both having stricter auth checks
	if _, err := rt.ut.authAPIKey(r, rt.bulker, rt.ut.cache); err != nil {
		writeUploadError(err, w, zlog, start, "authentication failure for chunk write")
		return
	}

	chunkNum, err := strconv.Atoi(chunkID)
	if err != nil {
		writeUploadError(uploader.ErrInvalidChunkNum, w, zlog, start, "error parsing chunk index")
		return
	}
	if err := rt.ut.handleUploadChunk(&zlog, w, r, id, chunkNum); err != nil {
		writeUploadError(err, w, zlog, start, "error uploading chunk")
		return
	}
}

func (rt Router) handleUploadComplete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	start := time.Now()

	id := ps.ByName("id")

	reqID := r.Header.Get(logger.HeaderRequestID)

	zlog := log.With().
		Str(LogAgentID, id).
		Str(ECSHTTPRequestID, reqID).
		Logger()

	// authentication occurs inside here, to ensure key agent ID
	// matches the same agent ID the operation started with
	if err := rt.ut.handleUploadComplete(&zlog, w, r, id); err != nil {
		writeUploadError(err, w, zlog, start, "error finalizing upload")
		return
	}
}

type UploadT struct {
	bulker      bulk.Bulk
	chunkClient *elasticsearch.Client
	cache       cache.Cache
	uploader    *uploader.Uploader
	authAgent   func(*http.Request, *string, bulk.Bulk, cache.Cache) (*model.Agent, error) // injectable for testing purposes
	authAPIKey  func(*http.Request, bulk.Bulk, cache.Cache) (*apikey.APIKey, error)        // as above
}

func NewUploadT(cfg *config.Server, bulker bulk.Bulk, chunkClient *elasticsearch.Client, cache cache.Cache) *UploadT {
	log.Info().
		Interface("limits", cfg.Limits.ArtifactLimit).
		Int64("maxFileSize", maxFileSize).
		Msg("upload limits")

	return &UploadT{
		chunkClient: chunkClient,
		bulker:      bulker,
		cache:       cache,
		uploader:    uploader.New(chunkClient, bulker, cache, maxFileSize, maxUploadTimer),
		authAgent:   authAgent,
		authAPIKey:  authAPIKey,
	}
}

func (ut *UploadT) handleUploadStart(_ *zerolog.Logger, w http.ResponseWriter, r *http.Request) error {
	// decode early to match agentID in the payload
	payload, err := uploader.ReadDict(r.Body)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("file info body is required: %w", err)
		}
		return err
	}

	// check API key matches payload agent ID
	agentID, ok := payload.Str("agent_id")
	if !ok || agentID == "" {
		return errors.New("required field agent_id is missing")
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
	out, err := json.Marshal(map[string]interface{}{
		"upload_id":  info.ID,
		"chunk_size": info.ChunkSize,
	})
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

func (ut *UploadT) handleUploadChunk(zlog *zerolog.Logger, w http.ResponseWriter, r *http.Request, uplID string, chunkID int) error {
	chunkHash := strings.TrimSpace(r.Header.Get("X-Chunk-Sha2"))
	if chunkHash == "" {
		return errors.New("chunk hash header required")
	}

	upinfo, chunkInfo, err := ut.uploader.Chunk(r.Context(), uplID, chunkID, chunkHash)
	if err != nil {
		return err
	}

	// prevent over-sized chunks
	data := http.MaxBytesReader(w, r.Body, uploader.MaxChunkSize)

	// compute hash as we stream it
	hash := sha256.New()
	copier := io.TeeReader(data, hash)

	ce := cbor.NewChunkWriter(copier, chunkInfo.Last, chunkInfo.BID, chunkInfo.SHA2, upinfo.ChunkSize)
	if err := uploader.IndexChunk(r.Context(), ut.chunkClient, ce, upinfo.Source, chunkInfo.BID, chunkInfo.Pos); err != nil {
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

	return nil
}

func (ut *UploadT) handleUploadComplete(_ *zerolog.Logger, w http.ResponseWriter, r *http.Request, uplID string) error {
	info, err := ut.uploader.GetUploadInfo(r.Context(), uplID)
	if err != nil {
		return err
	}
	// need to auth that it matches the ID in the initial
	// doc, but that means we had to doc-lookup early
	if _, err := ut.authAgent(r, &info.AgentID, ut.bulker, ut.cache); err != nil {
		return fmt.Errorf("Error authenticating for upload finalization: %w", err)
	}

	var req UploadCompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return errors.New("unable to parse request body")
	}

	hash := strings.TrimSpace(req.TransitHash.SHA256)
	if hash == "" {
		return errors.New("transit hash required")
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

// helper function for doing all the error responsibilities
// at the HTTP edge
func writeUploadError(err error, w http.ResponseWriter, zlog zerolog.Logger, start time.Time, msg string) {
	cntUpload.IncError(err)
	resp := NewHTTPErrResp(err)

	zlog.WithLevel(resp.Level).
		Err(err).
		Int(ECSHTTPResponseCode, resp.StatusCode).
		Int64(ECSEventDuration, time.Since(start).Nanoseconds()).
		Msg(msg)
	if e := resp.Write(w); e != nil {
		zlog.Error().Err(e).Msg("failure writing error response")
	}
}

type UploadCompleteRequest struct {
	TransitHash struct {
		SHA256 string `json:"sha256"`
	} `json:"transithash"`
}
