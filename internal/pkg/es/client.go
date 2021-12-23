// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package es

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"

	"github.com/elastic/fleet-server/v7/internal/pkg/build"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"

	"github.com/elastic/beats/v7/libbeat/common/cfgwarn"
	"github.com/elastic/go-elasticsearch/v7"
	"github.com/rs/zerolog/log"
)

type ConfigOption func(config elasticsearch.Config)

func NewClient(ctx context.Context, cfg *config.Config, longPoll bool, opts ...ConfigOption) (*elasticsearch.Client, error) {
	escfg, err := cfg.Output.Elasticsearch.ToESConfig(longPoll)
	if escfg.Password != "" {
		cfgwarn.Deprecate("8.0.0", "Basic authentication (username:password) is deprecated. Please use api_key.")
	}
	if err != nil {
		return nil, err
	}
	addr := cfg.Output.Elasticsearch.Hosts
	user := cfg.Output.Elasticsearch.Username
	mcph := cfg.Output.Elasticsearch.MaxConnPerHost

	// Apply configuration options
	for _, opt := range opts {
		opt(escfg)
	}

	zlog := log.With().
		Strs("cluster.addr", addr).
		Str("cluster.user", user).
		Int("cluster.maxConnsPersHost", mcph).
		Logger()

	zlog.Debug().Msg("init es")

	es, err := elasticsearch.NewClient(escfg)
	if err != nil {
		zlog.Error().Err(err).Msg("fail elasticsearch init")
		return nil, err
	}

	// Validate connection
	resp, err := info(ctx, es)
	if err != nil {
		zlog.Error().Err(err).Msg("fail elasticsearch info")
		return nil, err
	}

	zlog.Info().
		Str("cluster.name", resp.ClusterName).
		Str("cluster.uuid", resp.ClusterUUID).
		Str("cluster.version", resp.Version.Number).
		Msg("elasticsearch cluster info")

	return es, nil
}

func WithUserAgent(name string, bi build.Info) func(config elasticsearch.Config) {
	return func(config elasticsearch.Config) {
		ua := userAgent(name, bi)
		// Set User-Agent header
		if config.Header == nil {
			config.Header = http.Header{}
		}
		config.Header.Set("User-Agent", ua)
	}
}

func userAgent(name string, bi build.Info) string {
	return fmt.Sprintf("Elastic-%s/%s (%s; %s; %s; %s)",
		name,
		bi.Version, runtime.GOOS, runtime.GOARCH,
		bi.Commit, bi.BuildTime)
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
