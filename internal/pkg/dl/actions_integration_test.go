// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// +build integration

package dl

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	ftesting "fleet/internal/pkg/testing"
)

func TestSearchActionsQuery(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	now := time.Now().UTC()

	index, bulker, actions := ftesting.SetupActions(ctx, t, 1, 11)

	t.Run("all agents actions", func(t *testing.T) {

		foundActions, err := findActions(ctx, bulker, QueryAllAgentActions, index, map[string]interface{}{
			FieldSeqNo:      -1,
			FieldMaxSeqNo:   len(actions),
			FieldExpiration: now,
		})
		if err != nil {
			t.Fatal(err)
		}

		diff := cmp.Diff(len(actions), len(foundActions))
		if diff != "" {
			t.Fatal(diff)
		}
	})

}
