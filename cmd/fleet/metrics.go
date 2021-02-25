// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"context"
	"github.com/pkg/errors"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"

	"github.com/elastic/beats/v7/libbeat/api"
	"github.com/elastic/beats/v7/libbeat/cmd/instance/metrics"
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/monitoring"
)

func (f *FleetServer) initMetrics(ctx context.Context, cfg *config.Config) (*api.Server, error) {
	registry := monitoring.GetNamespace("info").GetRegistry()
	monitoring.NewString(registry, "version").Set(f.version)
	monitoring.NewString(registry, "name").Set("fleet-server")
	metrics.SetupMetrics("fleet-server")

	if !cfg.HTTP.Enabled {
		return nil, nil
	}

	// Start local api server; largely for metics.
	zapStub := logger.NewZapStub("fleet-metrics")
	cfgStub, err := common.NewConfigFrom(&cfg.HTTP)
	if err != nil {
		return nil, err
	}
	s, err := api.NewWithDefaultRoutes(zapStub, cfgStub, monitoring.GetNamespace)
	if err != nil {
		err = errors.Wrap(err, "could not start the HTTP server for the API")
	} else {
		s.Start()
	}

	return s, err
}
