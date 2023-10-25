// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration

package coordinator

import (
	"context"
	"testing"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/gofrs/uuid"
)

func TestCoordinatorZero(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	policyId := uuid.Must(uuid.NewV4()).String()
	policy := model.Policy{
		PolicyID:       policyId,
		CoordinatorIdx: 0,
		Data:           nil,
		RevisionIdx:    1,
	}
	coord, err := NewCoordinatorZero(policy)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		if err := coord.Run(ctx); err != nil && err != context.Canceled {
			t.Error(err)
			return
		}
	}()

	// should get a new policy on start up
	select {
	case newPolicy := <-coord.Output():
		if newPolicy.RevisionIdx != 1 {
			t.Fatalf("revision_idx should be set to 1, it was set to %d", newPolicy.RevisionIdx)
		}
		if newPolicy.CoordinatorIdx != 1 {
			t.Fatalf("coordinator_idx should be set to 1, it was set to %d", newPolicy.CoordinatorIdx)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("never receive a new policy")
	}

	// send a new policy revision; should get a new policy
	policy = model.Policy{
		PolicyID:       policyId,
		CoordinatorIdx: 0,
		Data:           nil,
		RevisionIdx:    2,
	}
	if err := coord.Update(ctx, policy); err != nil {
		t.Fatal(err)
	}
	select {
	case newPolicy := <-coord.Output():
		if newPolicy.RevisionIdx != 2 {
			t.Fatalf("revision_idx should be set to 2, it was set to %d", newPolicy.RevisionIdx)
		}
		if newPolicy.CoordinatorIdx != 1 {
			t.Fatalf("coordinator_idx should be set to 1, it was set to %d", newPolicy.CoordinatorIdx)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("never receive a new policy")
	}

	// send policy with already set coordinator_idx, v0 does nothing
	policy = model.Policy{
		PolicyID:       policyId,
		CoordinatorIdx: 1,
		Data:           nil,
		RevisionIdx:    2,
	}
	if err := coord.Update(ctx, policy); err != nil {
		t.Fatal(err)
	}
	select {
	case <-coord.Output():
		t.Fatal("should not have got a new policy")
	case <-time.After(500 * time.Millisecond):
		break
	}
}
