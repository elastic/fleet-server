// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package coordinator

import (
	"context"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"fleet/internal/pkg/model"
)

// coordinatorZeroT is V0 coordinator that just takes a subscribed policy and outputs the same policy.
type coordinatorZeroT struct {
	log zerolog.Logger

	policy model.Policy
	in     chan model.Policy
	out    chan model.Policy
}

// NewCoordinatorZero creates a V0 coordinator.
func NewCoordinatorZero(policy model.Policy) (Coordinator, error) {
	return &coordinatorZeroT{
		log:    log.With().Str("ctx", "coordinator v0").Str("policyId", policy.PolicyId).Logger(),
		policy: policy,
		in:     make(chan model.Policy, 1),
		out:    make(chan model.Policy),
	}, nil
}

// Name returns the "v0" name.
func (c *coordinatorZeroT) Name() string {
	return "v0"
}

// Run runs the coordinator for the policy.
func (c *coordinatorZeroT) Run(ctx context.Context) error {
	c.in <- c.policy
	for {
		select {
		case p := <-c.in:
			newData, err := c.handlePolicy(p.Data)
			if err != nil {
				c.log.Err(err).Msg("failed to handle policy")
				continue
			}
			if p.CoordinatorIdx == 0 {
				p.CoordinatorIdx = 1
				p.Data = newData
				c.policy = p
				c.out <- p
			} else if newData != p.Data {
				p.CoordinatorIdx += 1
				p.Data = newData
				c.policy = p
				c.out <- p
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Update called to signal a new policy revision has been defined.
func (c *coordinatorZeroT) Update(_ context.Context, policy model.Policy) error {
	c.in <- policy
	return nil
}

// Output is the output channel for updated coordinated policies.
func (c *coordinatorZeroT) Output() <-chan model.Policy {
	return c.out
}

// handlePolicy handles the new policy.
//
// Does nothing at the moment.
func (c *coordinatorZeroT) handlePolicy(data string) (string, error) {
	return data, nil
}
