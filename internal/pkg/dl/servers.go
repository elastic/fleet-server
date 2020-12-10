// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import (
	"bytes"
	"encoding/json"

	"github.com/elastic/go-elasticsearch/v8"

	"fleet/internal/pkg/model"
)

// EnsureServer ensures that this server is written in the index.
func EnsureServer(cli *elasticsearch.Client, version string, agent model.AgentMetadata, host model.HostMetadata) error {
	var server model.Server
	server.Agent = &agent
	server.Host = &host
	server.Server = &model.ServerMetadata{
		Id:      agent.Id,
		Version: version,
	}
	data, err := json.Marshal(&server)
	if err != nil {
		return err
	}
	_, err = cli.Update(FleetServers, agent.Id, bytes.NewBuffer(data))
	return err
}
