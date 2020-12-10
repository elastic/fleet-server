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
	in chan model.Policy
	out chan model.Policy
}

// NewCoordinatorZero creates a V0 coordinator.
func NewCoordinatorZero(policy model.Policy) (Coordinator, error) {
	return &coordinatorZeroT{
		log: log.With().Str("ctx", "coordinator v0").Str("policyId", policy.Id).Logger(),
		policy: policy,
		in: make(chan model.Policy, 1),
		out: make(chan model.Policy),
	}, nil
}

// Run runs the coordinator for the policy.
func (c *coordinatorZeroT) Run(ctx context.Context) (err error) {
	c.log.Info().Msg("Start")
	defer func() {
		c.log.Info().Err(err).Msg("Exited")
	}()

	c.in <- c.policy
	for {
		select {
		case p := <-c.in:
			newPolicy, err := c.handlePolicy(p)
			if err != nil {
				c.log.Err(err).Msg("failed to handle policy")
				continue
			}
			c.policy = newPolicy
			c.out <- newPolicy
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
// Just increments the coordinator index, does nothing else.
func (c *coordinatorZeroT) handlePolicy(p model.Policy) (model.Policy, error) {
	p.CoordinatorIdx += 1
	return p, nil
}
