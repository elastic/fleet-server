// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/rs/zerolog"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/file/delivery"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/go-elasticsearch/v8"
)

type FileDeliveryT struct {
	bulker    bulk.Bulk
	cache     cache.Cache
	deliverer *delivery.Deliverer
	authAgent func(*http.Request, *string, bulk.Bulk, cache.Cache) (*model.Agent, error) // injectable for testing purposes
}

func NewFileDeliveryT(cfg *config.Server, bulker bulk.Bulk, chunkClient *elasticsearch.Client, cache cache.Cache) *FileDeliveryT {
	return &FileDeliveryT{
		bulker:    bulker,
		cache:     cache,
		deliverer: delivery.New(chunkClient, bulker, cfg.Limits.MaxFileStorageByteSize),
		authAgent: authAgent,
	}
}

func (ft *FileDeliveryT) handleSendFile(zlog zerolog.Logger, w http.ResponseWriter, r *http.Request, fileID string) error {
	agent, err := ft.authAgent(r, nil, ft.bulker, ft.cache)
	if err != nil {
		return err
	}

	// find file
	info, err := ft.deliverer.FindFileForAgent(r.Context(), fileID, agent.Agent.ID)
	if err != nil {
		return err
	}

	chunks, err := ft.deliverer.LocateChunks(r.Context(), zlog, fileID)
	if errors.Is(err, delivery.ErrNoFile) {
		w.WriteHeader(http.StatusNotFound)
		return err
	}
	if err != nil {
		return err
	}

	// set headers before writing any chunks!

	// if mime_type was provided, set as Content-Type, otherwise fall back to octet-stream
	w.Header().Set("Content-Type", "application/octet-stream")
	if info.File.MimeType != "" {
		w.Header().Set("Content-Type", info.File.MimeType)
	}

	if info.File.Size > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(info.File.Size, 10))
	}

	if info.File.Hash != nil && info.File.Hash.SHA2 != "" {
		w.Header().Set("X-File-SHA2", info.File.Hash.SHA2)
	}

	// stream the chunks out
	return ft.deliverer.SendFile(r.Context(), zlog, w, chunks, fileID)
}
