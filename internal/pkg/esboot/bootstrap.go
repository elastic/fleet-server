// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package esboot

import (
	"context"
	"fleet/internal/pkg/es"
)

// Temporary ES indices bootstrapping until we move this logic to a proper place
// The plans at the moment possibly handle at ES plugin

type indexConfig struct {
	mapping    string
	datastream bool
}

var indexConfigs = map[string]indexConfig{
	".fleet-servers":         {mapping: kMappingServer},
	".fleet-policies":        {mapping: kMappingPolicy},
	".fleet-policies-leader": {mapping: kMappingPolicyLeader},
	".fleet-agents":          {mapping: kMappingAgent},
	".fleet-actions":         {mapping: kMappingAction},
	".fleet-actions-results": {mapping: kMappingActionResult, datastream: true},
}

// Bootstrap creates .fleet-actions data stream
func EnsureESIndices(ctx context.Context, client *es.Client) error {
	for name, idxcfg := range indexConfigs {
		err := EnsureDatastream(ctx, client, name, idxcfg)
		if err != nil {
			return err
		}
	}
	return nil
}

func EnsureDatastream(ctx context.Context, client *es.Client, name string, idxcfg indexConfig) error {
	if idxcfg.datastream {
		err := EnsureILMPolicy(ctx, client, name)
		if err != nil {
			return err
		}
	}

	err := EnsureTemplate(ctx, client, name, idxcfg.mapping, idxcfg.datastream)
	if err != nil {
		return err
	}

	if idxcfg.datastream {
		err = CreateDatastream(ctx, client, name)
	} else {
		err = CreateIndex(ctx, client, name)
	}
	if err != nil {
		return err
	}

	return nil
}
