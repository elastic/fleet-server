// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package gc

import (
	"context"
	"testing"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
)

func TestCleanupActions(t *testing.T) {
	tests := []struct {
		name       string
		selectSize int
	}{
		{
			name:       "index not found",
			selectSize: 5,
		},
		{
			name:       "one loop pass",
			selectSize: 1000,
		},
		{
			name:       "multiple loop passes",
			selectSize: 5,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testCleanupActionsWithSelectSize(t, tc.selectSize)
		})
	}
}

func testCleanupActionsWithSelectSize(t *testing.T, _ int) {
	const (
		thirtyDays        = "720h"
		thirtyDaysAndHour = "721h"
	)
	var (
		expiredActions, nonExpiredActions []model.Action
		err                               error
	)

	ctx := context.Background()
	ctx = testlog.SetLogger(t).WithContext(ctx)

	index, bulker := ftesting.SetupCleanIndex(ctx, t, dl.FleetActions)

	expiredActions, err = ftesting.CreateRandomActions(
		ftesting.CreateActionsWithMinAgentsCount(3),
		ftesting.CreateActionsWithMaxAgentsCount(7),
		ftesting.CreateActionsWithMinActionsCount(7),
		ftesting.CreateActionsWithMaxActionsCount(15),
		ftesting.CreateActionsWithTimestampOffset(-((24*30)+1)*time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}

	nonExpiredActions, err = ftesting.CreateRandomActions(
		ftesting.CreateActionsWithMinAgentsCount(3),
		ftesting.CreateActionsWithMaxAgentsCount(7),
		ftesting.CreateActionsWithMinActionsCount(7),
		ftesting.CreateActionsWithMaxActionsCount(15),
	)
	if err != nil {
		t.Fatal(err)
	}

	err = ftesting.StoreActions(ctx, bulker, index, append(expiredActions, nonExpiredActions...))
	if err != nil {
		t.Fatal(err)
	}

	if err != nil {
		t.Fatal(err)
	}

	err = cleanupActions(ctx, index, bulker,
		WithCleanupIntervalAfterExpired(thirtyDays))
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(time.Second)

	// Check that all expired actions where deleted
	hits, err := dl.FindExpiredActionsHitsForIndex(ctx, index, bulker, time.Now().Add(-24*30*time.Hour), 100)
	if err != nil {
		t.Fatal(err)
	}

	if err != nil {
		t.Fatal(err)
	}
	if len(hits) > 0 {
		t.Errorf("unexpected number of hits, got %d, want 0", len(hits))
	}

	// Check that non-expired actions are still there
	hits, err = dl.FindExpiredActionsHitsForIndex(ctx, index, bulker, time.Now().Add(time.Hour), 100)
	if err != nil {
		t.Fatal(err)
	}

	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != len(nonExpiredActions) {
		t.Errorf("unexpected number of hits, got %d, want %d", len(hits), len(nonExpiredActions))
	}
}
