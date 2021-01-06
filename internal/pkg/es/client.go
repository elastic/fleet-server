// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package es

import (
	"context"
	"encoding/json"
	"fmt"

	"fleet-server/internal/pkg/config"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/rs/zerolog/log"
)

func NewClient(ctx context.Context, cfg *config.Config) (*elasticsearch.Client, error) {
	escfg, err := cfg.Output.Elasticsearch.ToESConfig()
	if err != nil {
		return nil, err
	}
	addr := cfg.Output.Elasticsearch.Hosts
	user := cfg.Output.Elasticsearch.Username
	mcph := cfg.Output.Elasticsearch.MaxConnPerHost

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
	resp, err := info(ctx, es)
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

type InfoResponse struct {
	ClusterName string `json:"cluster_name"`
	ClusterUUID string `json:"cluster_uuid"`
	Version     struct {
		Number string `json:"number"`
	} `json:"version"`
}

func info(ctx context.Context, es *elasticsearch.Client) (*InfoResponse, error) {
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
