// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package checkin

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/sqn"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEffectiveConfigReplacesRemovedFields verifies that when a collector
// removes a pipeline from its configuration, the effective_config stored in
// Elasticsearch no longer contains the removed pipeline.
//
// Reproduces https://github.com/elastic/fleet-server/issues/6877
func TestEffectiveConfigReplacesRemovedFields(t *testing.T) {
	ctx := testlog.SetLogger(t).WithContext(t.Context())

	index, bulker := ftesting.SetupCleanIndex(ctx, t, dl.FleetAgents)
	agentID := uuid.Must(uuid.NewV7()).String()

	// Step 1: Create a document with effective_config containing 2 pipelines.
	now := time.Now().UTC().Format(time.RFC3339)
	initialConfig := json.RawMessage(`{"service":{"pipelines":{"traces":{"receivers":["otlp"],"exporters":["logging"]},"metrics":{"receivers":["otlp"],"exporters":["logging"]}}}}`)
	initialDoc, err := json.Marshal(model.Agent{
		Active:            true,
		EnrolledAt:        now,
		LastCheckin:       now,
		LastCheckinStatus: "online",
		UpdatedAt:         now,
		EffectiveConfig:   initialConfig,
	})
	require.NoError(t, err)

	_, err = bulker.Create(ctx, index, agentID, initialDoc, bulk.WithRefresh())
	require.NoError(t, err)

	// Step 2: Check in with effective_config containing only 1 pipeline
	// (metrics removed), then flush to ES.
	updatedConfig := []byte(`{"service":{"pipelines":{"traces":{"receivers":["otlp"],"exporters":["logging"]}}}}`)

	bc := NewBulk(bulker)
	err = bc.CheckIn(agentID,
		WithStatus("online"),
		WithEffectiveConfig(updatedConfig),
		WithSeqNo(sqn.SeqNo{1}), // triggers refresh on flush
	)
	require.NoError(t, err)

	err = bc.flush(ctx)
	require.NoError(t, err)

	// Step 3: Read the document back and verify the removed pipeline is gone.
	data, err := bulker.Read(ctx, index, agentID)
	require.NoError(t, err)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(data, &doc))

	ec, ok := doc["effective_config"].(map[string]any)
	require.True(t, ok, "effective_config should be present")

	service, ok := ec["service"].(map[string]any)
	require.True(t, ok)

	pipelines, ok := service["pipelines"].(map[string]any)
	require.True(t, ok)

	assert.Len(t, pipelines, 1, "effective_config should only contain the pipelines reported by the collector")
	assert.Contains(t, pipelines, "traces")
	assert.NotContains(t, pipelines, "metrics", "removed pipeline should not persist after update")
}
