// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// +build integration

package suite

import (
	"context"

	"github.com/stretchr/testify/require"
	tsuite "github.com/stretchr/testify/suite"

	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	"github.com/elastic/fleet-server/v7/internal/pkg/testing/esutil"
)

var prepareIndexes = map[string]string{
	dl.FleetActions:           es.MappingAction,
	dl.FleetActionsResults:    es.MappingActionResult,
	dl.FleetAgents:            es.MappingAgent,
	dl.FleetArtifacts:         es.MappingArtifact,
	dl.FleetEnrollmentAPIKeys: es.MappingEnrollmentApiKey,
	dl.FleetPolicies:          es.MappingPolicy,
	dl.FleetPoliciesLeader:    es.MappingPolicyLeader,
	dl.FleetServers:           es.MappingServer,
}

type RunningSuite struct {
	tsuite.Suite
}

func (s *RunningSuite) SetupSuite() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := ftesting.SetupBulk(ctx, s.T())
	for index, mapping := range prepareIndexes {
		err := esutil.EnsureIndex(ctx, c, index, mapping)
		require.NoError(s.T(), err)
	}
}

func (s *RunningSuite) TearDownSuite() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := ftesting.SetupBulk(ctx, s.T())
	names := make([]string, 0, len(prepareIndexes))
	for index, _ := range prepareIndexes {
		names = append(names, index)
	}
	err := esutil.DeleteIndices(ctx, c, names...)
	require.NoError(s.T(), err)
}
