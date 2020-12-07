// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package es

import (
	"context"
	"encoding/json"
	"fleet/internal/pkg/bulk"
	"fleet/internal/pkg/config"
	"fmt"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/rs/zerolog/log"
)

type InfoResponse struct {
	ClusterName string `json:"cluster_name"`
	ClusterUUID string `json:"cluster_uuid"`
	Version     struct {
		Number string `json:"number"`
	} `json:"version"`
}

func Info(ctx context.Context, es *elasticsearch.Client) (*InfoResponse, error) {
	// Validate the connection
	res, err := es.Info()

	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("info fail %v", res)
	}

	var resp InfoResponse

	d := json.NewDecoder(res.Body)
	if err = d.Decode(&resp); err != nil {
		return nil, err
	}

	return &resp, err
}

func InitClient(ctx context.Context, cfg *config.Elasticsearch) (*elasticsearch.Client, error) {

	escfg, err := cfg.ToESConfig()
	if err != nil {
		return nil, err
	}
	addr := cfg.Hosts
	user := cfg.Username
	mcph := cfg.MaxConnPerHost

	log.Debug().
		Strs("addr", addr).
		Str("user", user).
		Int("maxConnsPersHost", mcph).
		Msg("init es")

	es, err := elasticsearch.NewClient(escfg)
	if err != nil {
		return nil, err
	}

	// Validate connection
	resp, err := Info(ctx, es)
	if err != nil {
		return nil, err
	}

	log.Info().
		Str("name", resp.ClusterName).
		Str("uuid", resp.ClusterUUID).
		Str("vers", resp.Version.Number).
		Msg("Cluster Info")

	return es, nil
}

func Init(ctx context.Context, cfg *config.Elasticsearch) (*elasticsearch.Client, bulk.Bulk, error) {

	es, err := InitClient(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}

	flushInterval := cfg.BulkFlushInterval

	blk := bulk.NewBulker(es)
	go func() {
		err := blk.Run(ctx, bulk.WithFlushInterval(flushInterval))
		log.Info().Err(err).Msg("Bulker exit")
	}()

	return es, blk, nil
}
