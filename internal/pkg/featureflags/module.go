// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package featureflags is a self-contained feature flags evaluation service.
//
// It keeps the content of the definitions index (written by Kibana) in memory, serves OFREP
// evaluations and, optionally, reports the evaluation contexts it sees. Its only dependency on
// the rest of Fleet Server is its configuration; Elasticsearch is reached through the small
// esclient.Client interface, so the module can be extracted into its own service.
package featureflags

import (
	"context"
	"net/http"

	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/featureflags/esclient"
	"github.com/elastic/fleet-server/v7/internal/pkg/featureflags/observed"
	"github.com/elastic/fleet-server/v7/internal/pkg/featureflags/ofrep"
	"github.com/elastic/fleet-server/v7/internal/pkg/featureflags/store"
)

// Module is the feature flags service.
type Module struct {
	store     *store.Store
	syncer    *store.Syncer
	collector *observed.Collector
	handler   http.Handler
}

// New creates the module. Nothing is fetched until Run is called.
func New(cfg config.FeatureFlagsService, client esclient.Client, log zerolog.Logger) *Module {
	log = log.With().Str("mod", "featureflags").Logger()
	st := store.New()
	m := &Module{
		store: st,
		syncer: store.NewSyncer(client, st, store.SyncOptions{
			Index:          cfg.DefinitionsIndex,
			PollInterval:   cfg.PollInterval,
			PollOverlap:    cfg.PollOverlap,
			ResyncInterval: cfg.ResyncInterval,
		}, log),
	}

	opts := ofrep.Options{AllowedOrigins: cfg.CORS.AllowedOrigins}
	if oc := cfg.ObservedContexts; oc.Enabled {
		m.collector = observed.New(client, observed.Options{
			Index:                  cfg.ObservedContextsIndex,
			FlushInterval:          oc.FlushInterval,
			MaxNewContextsPerFlush: oc.MaxNewContextsPerFlush,
			LastSeenResolution:     oc.LastSeenResolution,
			ExcludeAttributes:      oc.ExcludeAttributes,
		}, log)
		opts.Observer = m.collector
	}
	m.handler = ofrep.NewHandler(st, opts)
	return m
}

// Run syncs the definitions and flushes observed contexts until ctx is done.
// Errors are retried internally, so it only returns ctx's error.
func (m *Module) Run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return m.syncer.Run(ctx) })
	if m.collector != nil {
		g.Go(func() error { return m.collector.Run(ctx) })
	}
	return g.Wait()
}

// Handler returns the OFREP HTTP handler, which serves the /ofrep/ paths.
func (m *Module) Handler() http.Handler {
	return m.handler
}

// Ready reports whether the definitions have been loaded.
func (m *Module) Ready() bool {
	return m.store.Ready()
}
