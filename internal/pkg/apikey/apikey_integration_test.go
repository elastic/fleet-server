// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration
// +build integration

package apikey

import (
	"context"
	"errors"
	"testing"

	"github.com/elastic/go-elasticsearch/v7"
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

func TestCreateAPIKeyWithMetadata(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

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
		NewMetadata(agentID, TypeAccess))
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

	// Try to get the key that doesn't exists, expect ErrApiKeyNotFound
	_, err = Read(ctx, es, "0000000000000", false)
	if !errors.Is(err, ErrAPIKeyNotFound) {
		t.Errorf("Unexpected error type: %v", err)
	}
}
