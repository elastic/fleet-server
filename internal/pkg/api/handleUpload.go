// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/limit"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/throttle"
	"github.com/elastic/fleet-server/v7/internal/pkg/upload"
	"github.com/julienschmidt/httprouter"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	// TODO: move to a config
	maxParallelUploads = 5

	// specification-designated maximum
	maxChunkSize = 4194304 // 4 MiB
)

func (rt Router) handleUploadStart(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	start := time.Now()

	reqID := r.Header.Get(logger.HeaderRequestID)

	zlog := log.With().
		Str(ECSHTTPRequestID, reqID).
		Logger()

	err := rt.ut.handleUploadStart(&zlog, w, r)

	if err != nil {
		cntUpload.IncError(err)
		resp := NewHTTPErrResp(err)

		// Log this as warn for visibility that limit has been reached.
		// This allows customers to tune the configuration on detection of threshold.
		if errors.Is(err, limit.ErrMaxLimit) || errors.Is(err, upload.ErrMaxConcurrentUploads) {
			resp.Level = zerolog.WarnLevel
		}

		zlog.WithLevel(resp.Level).
			Err(err).
			Int(ECSHTTPResponseCode, resp.StatusCode).
			Int64(ECSEventDuration, time.Since(start).Nanoseconds()).
			Msg("fail checkin")

		if err := resp.Write(w); err != nil {
			zlog.Error().Err(err).Msg("fail writing error response")
		}
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

	chunkNum, err := strconv.Atoi(chunkID)
	if err != nil {
		cntUpload.IncError(err)
		resp := NewHTTPErrResp(err)
		if err := resp.Write(w); err != nil {
			zlog.Error().Err(err).Msg("fail writing error response")
		}
		return
	}
	err = rt.ut.handleUploadChunk(&zlog, w, r, id, chunkNum)

	if err != nil {
		cntUpload.IncError(err)
		resp := NewHTTPErrResp(err)

		// Log this as warn for visibility that limit has been reached.
		// This allows customers to tune the configuration on detection of threshold.
		if errors.Is(err, limit.ErrMaxLimit) {
			resp.Level = zerolog.WarnLevel
		}

		zlog.WithLevel(resp.Level).
			Err(err).
			Int(ECSHTTPResponseCode, resp.StatusCode).
			Int64(ECSEventDuration, time.Since(start).Nanoseconds()).
			Msg("fail checkin")

		if err := resp.Write(w); err != nil {
			zlog.Error().Err(err).Msg("fail writing error response")
		}
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

	err := rt.ut.handleUploadComplete(&zlog, w, r, id)

	if err != nil {
		cntUpload.IncError(err)
		resp := NewHTTPErrResp(err)

		// Log this as warn for visibility that limit has been reached.
		// This allows customers to tune the configuration on detection of threshold.
		if errors.Is(err, limit.ErrMaxLimit) {
			resp.Level = zerolog.WarnLevel
		}

		zlog.WithLevel(resp.Level).
			Err(err).
			Int(ECSHTTPResponseCode, resp.StatusCode).
			Int64(ECSEventDuration, time.Since(start).Nanoseconds()).
			Msg("fail checkin")

		if err := resp.Write(w); err != nil {
			zlog.Error().Err(err).Msg("fail writing error response")
		}
	}
}

type UploadT struct {
	bulker     bulk.Bulk
	cache      cache.Cache
	esThrottle *throttle.Throttle
	upl        *upload.Uploader
}

func NewUploadT(cfg *config.Server, bulker bulk.Bulk, cache cache.Cache) *UploadT {
	log.Info().
		Interface("limits", cfg.Limits.ArtifactLimit).
		Int("maxParallel", defaultMaxParallel).
		Msg("Artifact install limits")

	return &UploadT{
		bulker:     bulker,
		cache:      cache,
		esThrottle: throttle.NewThrottle(defaultMaxParallel),
		upl:        upload.New(maxParallelUploads),
	}
}

func (ut *UploadT) handleUploadStart(zlog *zerolog.Logger, w http.ResponseWriter, r *http.Request) error {
	var fi FileInfo
	if err := json.NewDecoder(r.Body).Decode(&fi); err != nil {
		r.Body.Close()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("file info body is required: %w", err)
		}
		return err
	}
	r.Body.Close()

	if strings.TrimSpace(fi.Name) == "" {
		return errors.New("file name is required")
	}
	if fi.Size <= 0 {
		return errors.New("invalid file size, size is required")
	}

	uploadID, err := ut.upl.Begin()
	if err != nil {
		return err
	}

	// TODO: write header doc

	_, err = w.Write([]byte(uploadID))
	if err != nil {
		return err
	}
	return nil
}

func (ut *UploadT) handleUploadChunk(zlog *zerolog.Logger, w http.ResponseWriter, r *http.Request, uplID string, chunkID int) error {
	// prevent over-sized chunks
	chunk := http.MaxBytesReader(w, r.Body, maxChunkSize)
	data, err := ut.upl.Chunk(uplID, chunkID, chunk)
	if err != nil {
		return err
	}

	_, err = w.Write([]byte(data))
	if err != nil {
		return err
	}
	return nil
}

func (ut *UploadT) handleUploadComplete(zlog *zerolog.Logger, w http.ResponseWriter, r *http.Request, uplID string) error {
	data, err := ut.upl.Complete(uplID)
	if err != nil {
		return err
	}

	_, err = w.Write([]byte(data))
	if err != nil {
		return err
	}
	return nil
}
