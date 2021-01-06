// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import (
	"context"
	"encoding/json"
	"time"

	"fleet-server/internal/pkg/bulk"
	"fleet-server/internal/pkg/es"
	"fleet-server/internal/pkg/model"
)

// EnsureServer ensures that this server is written in the index.
func EnsureServer(ctx context.Context, bulker bulk.Bulk, version string, agent model.AgentMetadata, host model.HostMetadata, opts ...Option) error {
	var server model.Server
	o := newOption(FleetServers, opts...)
	data, err := bulker.Read(ctx, o.indexName, agent.Id)
	if err != nil && err != es.ErrElasticNotFound {
		return err
	}
	if err == es.ErrElasticNotFound {
		server.Agent = &agent
		server.Host = &host
		server.Server = &model.ServerMetadata{
			Id:      agent.Id,
			Version: version,
		}
		server.SetTime(time.Now().UTC())
		data, err = json.Marshal(&server)
		if err != nil {
			return err
		}
		_, err = bulker.Create(ctx, o.indexName, agent.Id, data)
		return err
	}
	err = json.Unmarshal(data, &server)
	if err != nil {
		return err
	}
	server.Agent = &agent
	server.Host = &host
	server.Server = &model.ServerMetadata{
		Id:      agent.Id,
		Version: version,
	}
	server.SetTime(time.Now().UTC())
	data, err = json.Marshal(&struct {
		Doc model.Server `json:"doc"`
	}{server})
	if err != nil {
		return err
	}
	return bulker.Update(ctx, o.indexName, agent.Id, data)
}
