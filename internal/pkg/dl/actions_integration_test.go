// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package dl

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/elastic/fleet-server/v7/internal/pkg/gcheckpt"
	ftesting "github.com/elastic/fleet-server/v7/internal/pkg/testing"
)

func TestSearchActionsQuery(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	now := time.Now().UTC()

	index, bulker, actions := ftesting.SetupActions(ctx, t, 1, 11)

	checkpoint, err := gcheckpt.Query(ctx, bulker.Client(), index)
	if err != nil {
		t.Fatal(err)
	}

	maxSeqNo := checkpoint.Value()
	minSeqNo := maxSeqNo - int64(len(actions))

	t.Run("all agents actions", func(t *testing.T) {

		foundActions, err := findActions(ctx, bulker, QueryAllAgentActions, index, map[string]interface{}{
			FieldSeqNo:      minSeqNo,
			FieldMaxSeqNo:   maxSeqNo,
			FieldExpiration: now,
		}, nil)
		if err != nil {
			t.Fatal(err)
		}

		diff := cmp.Diff(len(actions), len(foundActions))
		if diff != "" {
			t.Fatal(diff)
		}
	})

}
