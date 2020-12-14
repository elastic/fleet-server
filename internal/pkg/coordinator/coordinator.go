// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package coordinator

import (
	"context"

	"fleet/internal/pkg/model"
)

// Factory creates a new coordinator for a policy.
type Factory func(policy model.Policy) (Coordinator, error)

// Coordinator processes a policy and produces a new policy.
type Coordinator interface {
	// Name is the name of the coordinator
	Name() string

	// Run runs the coordinator for the policy.
	Run(ctx context.Context) error

	// Update called to signal a new policy revision has been defined.
	//
	// This should not block as its called by the main loop in the coordinator manager. The implemented coordinator
	// should push it over a channel for the work to be done in another go routine.
	Update(ctx context.Context, policy model.Policy) error

	// Output is the output channel for updated coordinated policies.
	Output() <-chan model.Policy
}
