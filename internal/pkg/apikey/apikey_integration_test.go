// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// +build integration

package apikey

import (
	"context"
	"errors"
	"testing"

	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"

	"github.com/gofrs/uuid"
	"github.com/google/go-cmp/cmp"
)

const testFleetRoles = `
{
	"fleet-apikey-access": {
		"cluster": [],
		"applications": [{
			"application": ".fleet",
			"privileges": ["no-privileges"],
			"resources": ["*"]
		}]
	}
}
`

func TestCreateApiKeyWithMetadata(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	bulker := ftesting.SetupBulk(ctx, t)

	// Create the key
	agentId := uuid.Must(uuid.NewV4()).String()
	name := uuid.Must(uuid.NewV4()).String()
	akey, err := Create(ctx, bulker.Client(), name, "", []byte(testFleetRoles),
		Metadata{
			Application: FleetAgentApplication,
			AgentId:     agentId,
			Type:        TypeAccess.String(),
		})
	if err != nil {
		t.Fatal(err)
	}

	// Get the key and verify that metadata was saved correctly
	aKeyMeta, err := Get(ctx, bulker.Client(), akey.Id)
	if err != nil {
		t.Fatal(err)
	}

	diff := cmp.Diff(FleetAgentApplication, aKeyMeta.Metadata.Application)
	if diff != "" {
		t.Error(diff)
	}

	diff = cmp.Diff(agentId, aKeyMeta.Metadata.AgentId)
	if diff != "" {
		t.Error(diff)
	}

	diff = cmp.Diff(TypeAccess.String(), aKeyMeta.Metadata.Type)
	if diff != "" {
		t.Error(diff)
	}

	// Try to get the key that doesn't exists, expect ErrApiKeyNotFound
	aKeyMeta, err = Get(ctx, bulker.Client(), "0000000000000")
	if !errors.Is(err, ErrApiKeyNotFound) {
		t.Errorf("Unexpected error type: %v", err)
	}
}
