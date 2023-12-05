// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package apikey

import (
	"context"
	"errors"
	"testing"

	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/gofrs/uuid"
	"github.com/google/go-cmp/cmp"
)

const testFleetRoles = `
{
	"fleet-apikey-access": {
		"cluster": [],
		"applications": [{
			"application": "fleet",
			"privileges": ["no-privileges"],
			"resources": ["*"]
		}]
	}
}
`

func TestRead_existingKey(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()
	ctx = testlog.SetLogger(t).WithContext(ctx)

	cfg := elasticsearch.Config{
		Username: "elastic",
		Password: "changeme",
	}

	es, err := elasticsearch.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Create the key
	agentID := uuid.Must(uuid.NewV4()).String()
	name := uuid.Must(uuid.NewV4()).String()
	akey, err := Create(ctx, es, name, "", "true", []byte(testFleetRoles),
		NewMetadata(agentID, "", TypeAccess))
	if err != nil {
		t.Fatal(err)
	}

	// Get the key and verify that metadata was saved correctly
	aKeyMeta, err := Read(ctx, es, akey.ID, false)
	if err != nil {
		t.Fatal(err)
	}

	diff := cmp.Diff(ManagedByFleetServer, aKeyMeta.Metadata.ManagedBy)
	if diff != "" {
		t.Error(diff)
	}

	diff = cmp.Diff(true, aKeyMeta.Metadata.Managed)
	if diff != "" {
		t.Error(diff)
	}

	diff = cmp.Diff(agentID, aKeyMeta.Metadata.AgentID)
	if diff != "" {
		t.Error(diff)
	}

	diff = cmp.Diff(TypeAccess.String(), aKeyMeta.Metadata.Type)
	if diff != "" {
		t.Error(diff)
	}

}

func TestRead_noKey(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()
	ctx = testlog.SetLogger(t).WithContext(ctx)

	cfg := elasticsearch.Config{
		Username: "elastic",
		Password: "changeme",
	}

	es, err := elasticsearch.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Try to get the key that doesn't exist, expect ErrApiKeyNotFound
	_, err = Read(ctx, es, "0000000000000", false)
	if !errors.Is(err, ErrAPIKeyNotFound) {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestCreateAPIKeyWithMetadata(t *testing.T) {
	tts := []struct {
		name       string
		outputName string
	}{
		{name: "with metadata.output_name", outputName: "a_output_name"},
		{name: "without metadata.output_name"},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cn := context.WithCancel(context.Background())
			defer cn()
			ctx = testlog.SetLogger(t).WithContext(ctx)

			cfg := elasticsearch.Config{
				Username: "elastic",
				Password: "changeme",
			}

			es, err := elasticsearch.NewClient(cfg)
			if err != nil {
				t.Fatal(err)
			}

			// Create the API key
			agentID := uuid.Must(uuid.NewV4()).String()
			name := uuid.Must(uuid.NewV4()).String()
			outputName := tt.outputName
			apiKey, err := Create(
				ctx,
				es,
				name,
				"",
				"true",
				[]byte(testFleetRoles),
				NewMetadata(agentID, outputName, TypeAccess))
			if err != nil {
				t.Fatal(err)
			}

			// Get the API key and verify that the metadata was saved correctly
			aKeyMeta, err := Read(ctx, es, apiKey.ID, false)
			if err != nil {
				t.Fatal(err)
			}

			diff := cmp.Diff(ManagedByFleetServer, aKeyMeta.Metadata.ManagedBy)
			if diff != "" {
				t.Error(diff)
			}

			diff = cmp.Diff(true, aKeyMeta.Metadata.Managed)
			if diff != "" {
				t.Error(diff)
			}

			diff = cmp.Diff(agentID, aKeyMeta.Metadata.AgentID)
			if diff != "" {
				t.Error(diff)
			}

			diff = cmp.Diff(outputName, aKeyMeta.Metadata.OutputName)
			if diff != "" {
				t.Error(diff)
			}

			diff = cmp.Diff(TypeAccess.String(), aKeyMeta.Metadata.Type)
			if diff != "" {
				t.Error(diff)
			}
		})
	}
}
