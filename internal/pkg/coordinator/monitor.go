package coordinator

import (
	"context"
	"encoding/json"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"fleet/internal/pkg/action"
	"fleet/internal/pkg/bulk"
	"fleet/internal/pkg/dl"
	"fleet/internal/pkg/model"
)

const (
	defaultCheckInterval  = 20 * time.Second  // check for valid leaders every 20 seconds
	defaultLeaderInterval = 30 * time.Second  // become leader for at least 30 seconds
)

// Monitor monitors the leader election of policies and routes managed policies to the coordinator.
type Monitor interface {
	// Run runs the monitor.
	Run(context.Context) error
}

type policyT struct {
	cord      Coordinator
	canceller context.CancelFunc
}

type monitorT struct {
	log zerolog.Logger

	bulker bulk.Bulk
	monitor *action.Monitor
	factory CoordinatorFactory

	checkInterval time.Duration
	leaderInterval time.Duration

	policies map[string]policyT
}

// NewMonitor creates a new coordinator policy monitor.
func NewMonitor(bulker bulk.Bulk, monitor *action.Monitor, factory CoordinatorFactory) Monitor {
	return &monitorT{
		log: log.With().Str("index", dl.FleetPoliciesLeader).Str("ctx", "policy leader manager").Logger(),
		bulker: bulker,
		monitor: monitor,
		factory: factory,
		checkInterval: defaultCheckInterval,
		leaderInterval: defaultLeaderInterval,
	}
}

// Run runs the monitor.
func (m *monitorT) Run(ctx context.Context) (err error) {
	m.log.Info().Msg("Start")
	defer func() {
		m.log.Info().Err(err).Msg("Exited")
	}()

	// Ensure leadership on startup
	err = m.ensureLeadership(ctx)
	if err != nil {
		return err
	}

	// Start timer loop to ensure leadership
	t := time.NewTimer(m.checkInterval)
	defer t.Stop()
	for {
		select {
		case hits := <-m.monitor.Output():
			err = m.handlePolicies(ctx, hits)
			if err != nil {
				return err
			}
		case <-t.C:
			err = m.ensureLeadership(ctx)
			if err != nil {
				return err
			}
			t.Reset(m.checkInterval)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// handlePolicies handles new policies or policy changes.
func (m *monitorT) handlePolicies(ctx context.Context, hits []bulk.HitT) error {
	new := false
	for _, hit := range hits {
		var policy model.Policy
		err := json.Unmarshal(hit.Source, &policy)
		if err != nil {
			return err
		}
		if policy.CoordinatorIdx != 0 {
			// policy revision was inserted by coordinator so this monitor ignores it
			continue
		}
		p, ok := m.policies[policy.PolicyId]
		if ok {
			// not a new policy
			if p.cord != nil {
				// current leader send to its coordinator
				err = p.cord.Update(ctx, policy)
				if err != nil {
					return err
				}
			}
		} else {
			new = true
		}
	}
	if new {
		// new policy discovered; leadership needs to be performed
		err := m.ensureLeadership(ctx)
		if err != nil {
			return err
		}
	}
	return nil
}

// ensureLeadership ensures leadership is held or needs to be taken over.
func (m *monitorT) ensureLeadership(ctx context.Context) error {

	return nil
}
