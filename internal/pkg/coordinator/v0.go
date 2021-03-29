// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package coordinator

import (
	"context"
	"encoding/json"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/elastic/fleet-server/v7/internal/pkg/model"
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
		in:     make(chan model.Policy),
		out:    make(chan model.Policy),
	}, nil
}

// Name returns the "v0" name.
func (c *coordinatorZeroT) Name() string {
	return "v0"
}

// Run runs the coordinator for the policy.
func (c *coordinatorZeroT) Run(ctx context.Context) error {
	err := c.updatePolicy(c.policy)
	if err != nil {
		c.log.Err(err).Msg("failed to handle policy")
	}

	for {
		select {
		case p := <-c.in:
			err = c.updatePolicy(p)
			if err != nil {
				c.log.Err(err).Msg("failed to handle policy")
				continue
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

// updatePolicy performs the working of incrementing the coordinator idx.
func (c *coordinatorZeroT) updatePolicy(p model.Policy) error {
	newData, err := c.handlePolicy(p.Data)
	if err != nil {
		return err
	}
	if p.CoordinatorIdx == 0 || string(newData) != string(p.Data) {
		p.CoordinatorIdx += 1
		p.Data = newData
		c.policy = p
		c.out <- p
	}
	return nil
}

// handlePolicy performs the actual work of coordination.
//
// Does nothing at the moment.
func (c *coordinatorZeroT) handlePolicy(data json.RawMessage) (json.RawMessage, error) {
	return data, nil
}
