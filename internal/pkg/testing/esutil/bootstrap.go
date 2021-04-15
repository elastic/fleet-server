// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package esutil

import (
	"context"

	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/go-elasticsearch/v8"
)

// Temporary ES indices bootstrapping until we move this logic to a proper place
// The plans at the moment possibly handle at ES plugin

type indexConfig struct {
	mapping    string
	datastream bool
}

var indexConfigs = map[string]indexConfig{
	// Commenting out the boostrapping for now here, just in case if it needs to be "enabled" again.
	// Will remove all the boostrapping code completely later once all is fully integrated
	".fleet-actions-results": {mapping: es.MappingActionResult, datastream: true},
}

// Bootstrap creates .fleet-actions data stream
func EnsureESIndices(ctx context.Context, cli *elasticsearch.Client) error {
	for name, idxcfg := range indexConfigs {
		err := EnsureDatastream(ctx, cli, name, idxcfg)
		if err != nil {
			return err
		}
	}
	return nil
}

func EnsureDatastream(ctx context.Context, cli *elasticsearch.Client, name string, idxcfg indexConfig) error {
	if idxcfg.datastream {
		err := EnsureILMPolicy(ctx, cli, name)
		if err != nil {
			return err
		}
	}

	err := EnsureTemplate(ctx, cli, name, idxcfg.mapping, idxcfg.datastream)
	if err != nil {
		return err
	}

	if idxcfg.datastream {
		err = CreateDatastream(ctx, cli, name)
	} else {
		err = CreateIndex(ctx, cli, name)
	}
	if err != nil {
		return err
	}

	return nil
}

func EnsureIndex(ctx context.Context, cli *elasticsearch.Client, name, mapping string) error {
	err := EnsureTemplate(ctx, cli, name, mapping, false)
	if err != nil {
		return err
	}
	return CreateIndex(ctx, cli, name)
}
