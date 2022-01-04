// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration
// +build integration

package dl

import (
	"context"
	"encoding/json"
	"runtime"
	"testing"

	"github.com/gofrs/uuid"

	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
)

func TestEnsureServer(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	index, bulker := ftesting.SetupCleanIndex(ctx, t, FleetServers)

	agentId := uuid.Must(uuid.NewV4()).String()
	agent := model.AgentMetadata{
		Id:      agentId,
		Version: "1.0.0",
	}
	host := model.HostMetadata{
		Architecture: runtime.GOOS,
		Id:           agentId,
		Ip:           []string{"::1"},
		Name:         "testing-host",
	}

	err := EnsureServer(ctx, bulker, "1.0.0", agent, host, WithIndexName(index))
	if err != nil {
		t.Fatal(err)
	}

	var srv model.Server
	data, err := bulker.Read(ctx, index, agentId)
	if err != nil {
		t.Fatal(err)
	}
	err = json.Unmarshal(data, &srv)
	if err != nil {
		t.Fatal(err)
	}
	if srv.Agent.Id != agentId {
		t.Fatal("agent.id should match agentId")
	}
}
