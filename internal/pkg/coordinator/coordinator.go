package coordinator

import (
	"context"

	"fleet/internal/pkg/model"
)

// CoordinatorFactory creates a new coordinator for a policy.
type CoordinatorFactory func (policy model.Policy) (Coordinator, error)

// Coordinator processes a policy and produces a new policy.
type Coordinator interface {
	// Run runs the coordinator for the policy.
	Run(ctx context.Context) error

	// Update called to signal a new policy revision has been defined.
	Update(ctx context.Context, policy model.Policy) error

	// Output is the output channel for updated coordinated policies.
	Output() <-chan model.Policy
}

