// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package coordinator

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/monitor"
	"github.com/elastic/fleet-server/v7/internal/pkg/sleep"
)

const (
	defaultCheckInterval           = 20 * time.Second // check for valid leaders every 20 seconds
	defaultLeaderInterval          = 30 * time.Second // become leader for at least 30 seconds
	defaultMetadataInterval        = 5 * time.Minute  // update metadata every 5 minutes
	defaultCoordinatorRestartDelay = 5 * time.Second  // delay in restarting coordinator on failure
)

// Monitor monitors the leader election of policies and routes managed policies to the coordinator.
type Monitor interface {
	// Run runs the monitor.
	Run(context.Context) error
}

type policyT struct {
	id            string
	cord          Coordinator
	cordCanceller context.CancelFunc
}

type monitorT struct {
	log zerolog.Logger

	bulker  bulk.Bulk
	monitor monitor.Monitor
	factory Factory

	fleet         config.Fleet
	version       string
	agentMetadata model.AgentMetadata
	hostMetadata  model.HostMetadata

	checkInterval     time.Duration
	leaderInterval    time.Duration
	metadataInterval  time.Duration
	coordRestartDelay time.Duration

	serversIndex  string
	policiesIndex string
	leadersIndex  string
	agentsIndex   string

	policies map[string]policyT

	muPoliciesCanceller sync.Mutex
	policiesCanceller   map[string]context.CancelFunc
}

// NewMonitor creates a new coordinator policy monitor.
func NewMonitor(fleet config.Fleet, version string, bulker bulk.Bulk, monitor monitor.Monitor, factory Factory) Monitor {
	return &monitorT{
		log:               log.With().Str("ctx", "policy leader manager").Logger(),
		version:           version,
		fleet:             fleet,
		bulker:            bulker,
		monitor:           monitor,
		factory:           factory,
		checkInterval:     defaultCheckInterval,
		leaderInterval:    defaultLeaderInterval,
		metadataInterval:  defaultMetadataInterval,
		coordRestartDelay: defaultCoordinatorRestartDelay,
		serversIndex:      dl.FleetServers,
		policiesIndex:     dl.FleetPolicies,
		leadersIndex:      dl.FleetPoliciesLeader,
		agentsIndex:       dl.FleetAgents,
		policies:          make(map[string]policyT),
		policiesCanceller: make(map[string]context.CancelFunc),
	}
}

// Run runs the monitor.
func (m *monitorT) Run(ctx context.Context) (err error) {
	// When ID of the Agent is not provided to Fleet Server then the Agent
	// has not enrolled. The Fleet Server cannot become a leader until the
	// Agent it is running under has been enrolled.
	m.calcMetadata()
	if m.agentMetadata.ID == "" {
		m.log.Warn().Msg("missing config fleet.agent.id; acceptable until Elastic Agent has enrolled")
		<-ctx.Done()
		return ctx.Err()
	}

	// Ensure leadership on startup
	err = m.ensureLeadership(ctx)
	if err != nil {
		return err
	}

	// Subscribe to the monitor for policies
	s := m.monitor.Subscribe()
	defer m.monitor.Unsubscribe(s)

	// Start timer to update metadata (mainly for updated IP addresses of the host)
	mT := time.NewTimer(m.metadataInterval)
	defer mT.Stop()

	// Start timer loop to ensure leadership
	lT := time.NewTimer(m.checkInterval)
	defer lT.Stop()

	// Keep track of errored statuses
	erroredOnLastRequest := false
	numFailedRequests := 0
	for {
		select {
		case hits := <-s.Output():
			err = m.handlePolicies(ctx, hits)
			if err != nil {
				erroredOnLastRequest = true
				numFailedRequests++
				m.log.Warn().Err(err).Msgf("Encountered an error while policy leadership changes; continuing to retry.")
			}
		case <-mT.C:
			m.calcMetadata()
			mT.Reset(m.metadataInterval)
		case <-lT.C:
			err = m.ensureLeadership(ctx)
			if err != nil {
				erroredOnLastRequest = true
				numFailedRequests++
				m.log.Warn().Err(err).Msgf("Encountered an error while checking/assigning policy leaders; continuing to retry.")
			}
			lT.Reset(m.checkInterval)
		case <-ctx.Done():
			m.releaseLeadership()
			return ctx.Err()
		}
		if err == nil && erroredOnLastRequest {
			erroredOnLastRequest = false
			m.log.Info().Msgf("Policy leader monitor successfully recovered after %d attempts", numFailedRequests)
			numFailedRequests = 0
		}
	}
}

// handlePolicies handles new policies or policy changes.
func (m *monitorT) handlePolicies(ctx context.Context, hits []es.HitT) error {
	new := false
	for _, hit := range hits {
		var policy model.Policy
		err := hit.Unmarshal(&policy)
		if err != nil {
			m.log.Debug().Err(err).Msg("Failed to deserialize policy json")
			return err
		}
		if policy.CoordinatorIdx != 0 {
			// policy revision was inserted by coordinator so this monitor ignores it
			continue
		}
		p, ok := m.policies[policy.PolicyID]
		if ok {
			// not a new policy
			if p.cord != nil {
				// current leader send to its coordinator
				err = p.cord.Update(ctx, policy)
				if err != nil {
					m.log.Info().Err(err).Msg("Failed to update policy leader")
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
	m.log.Debug().Msg("ensuring leadership of policies")
	err := dl.EnsureServer(ctx, m.bulker, m.version, m.agentMetadata, m.hostMetadata, dl.WithIndexName(m.serversIndex))

	if err != nil {
		return fmt.Errorf("failed to check server status on Elasticsearch (%s): %w", m.hostMetadata.Name, err)
	}

	// fetch current policies and leaders
	leaders := map[string]model.PolicyLeader{}
	policies, err := dl.QueryLatestPolicies(ctx, m.bulker, dl.WithIndexName(m.policiesIndex))
	if err != nil {
		if errors.Is(err, es.ErrIndexNotFound) {
			m.log.Debug().Str("index", m.policiesIndex).Msg(es.ErrIndexNotFound.Error())
			return nil
		}
		return fmt.Errorf("encountered error while querying policies: %w", err)
	}
	if len(policies) > 0 {
		ids := make([]string, len(policies))
		for i, p := range policies {
			ids[i] = p.PolicyID
		}
		leaders, err = dl.SearchPolicyLeaders(ctx, m.bulker, ids, dl.WithIndexName(m.leadersIndex))
		if err != nil {
			if !errors.Is(err, es.ErrIndexNotFound) {
				return fmt.Errorf("encountered error while fetching policy leaders: %w", err)
			}
		}
	}

	// determine the policies that lead needs to be taken
	var lead []model.Policy
	now := time.Now().UTC()
	for _, policy := range policies {
		leader, ok := leaders[policy.PolicyID]
		if !ok {
			// new policy want to try to take leadership
			lead = append(lead, policy)
			continue
		}
		t, err := leader.Time()
		if err != nil {
			return err
		}
		if now.Sub(t) > m.leaderInterval || leader.Server.ID == m.agentMetadata.ID {
			// policy needs a new leader or already leader
			lead = append(lead, policy)
		}
	}

	// take/keep leadership and start new coordinators
	res := make(chan policyT)
	for _, p := range lead {
		pt := m.policies[p.PolicyID]
		pt.id = p.PolicyID
		go func(p model.Policy, pt policyT) {
			defer func() {
				res <- pt
			}()

			l := m.log.With().Str(dl.FieldPolicyID, pt.id).Logger()
			err := dl.TakePolicyLeadership(ctx, m.bulker, pt.id, m.agentMetadata.ID, m.version, dl.WithIndexName(m.leadersIndex))
			if err != nil {
				l.Err(err).Msg("failed to take ownership")
				if pt.cord != nil {
					pt.cord = nil
				}
				if pt.cordCanceller != nil {
					pt.cordCanceller()
					pt.cordCanceller = nil
				}
				return
			}
			if pt.cord == nil {
				cord, err := m.factory(p)
				if err != nil {
					l.Err(err).Msg("failed to start coordinator")
					err = dl.ReleasePolicyLeadership(ctx, m.bulker, pt.id, m.agentMetadata.ID, m.leaderInterval, dl.WithIndexName(m.leadersIndex))
					if err != nil {
						l.Err(err).Msg("failed to release policy leadership")
					}
					return
				}

				cordCtx, canceller := context.WithCancel(ctx)
				go runCoordinator(cordCtx, cord, l, m.coordRestartDelay)
				go runCoordinatorOutput(cordCtx, cord, m.bulker, l, m.policiesIndex)
				pt.cord = cord
				pt.cordCanceller = canceller
			} else {
				err = pt.cord.Update(ctx, p)
				if err != nil {
					l.Err(err).Msg("failed to update coordinator")
				}
			}
		}(p, pt)
	}
	for range lead {
		r := <-res
		if r.cord == nil {
			// either failed to take leadership or lost leadership
			delete(m.policies, r.id)

			m.muPoliciesCanceller.Lock()
			delete(m.policiesCanceller, r.id)
			m.muPoliciesCanceller.Unlock()
		} else {
			m.policies[r.id] = r
		}
	}
	return nil
}

// releaseLeadership releases current leadership
func (m *monitorT) releaseLeadership() {
	var wg sync.WaitGroup
	wg.Add(len(m.policies))
	for _, pt := range m.policies {
		go func(pt policyT) {
			if pt.cord != nil {
				pt.cordCanceller()
			}
			// uses a background context, because the context for the
			// monitor will be cancelled at this point in the code
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := dl.ReleasePolicyLeadership(ctx, m.bulker, pt.id, m.agentMetadata.ID, m.leaderInterval, dl.WithIndexName(m.leadersIndex))
			if err != nil {
				l := m.log.With().Str(dl.FieldPolicyID, pt.id).Logger()
				l.Err(err).Msg("failed to release leadership")
			}
			wg.Done()
		}(pt)
	}
	wg.Wait()
}

func (m *monitorT) calcMetadata() {
	m.agentMetadata = model.AgentMetadata{
		ID:      m.fleet.Agent.ID,
		Version: m.fleet.Agent.Version,
	}
	hostname := m.fleet.Host.Name
	if hostname == "" {
		h, err := os.Hostname()
		if err != nil {
			m.log.Err(err).Msg("failed to get hostname")
		}
		hostname = h
	}
	ips, err := m.getIPs()
	if err != nil {
		m.log.Err(err).Msg("failed to get ip addresses")
	}
	m.hostMetadata = model.HostMetadata{
		ID:           m.fleet.Host.ID,
		Name:         hostname,
		Architecture: runtime.GOOS,
		Ip:           ips,
	}
}

func (m *monitorT) getIPs() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	ips := []string{}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil {
				ips = append(ips, ip.String())
			}
		}
	}
	return ips, nil
}

func runCoordinator(ctx context.Context, cord Coordinator, l zerolog.Logger, d time.Duration) {
	cnt := 0
	for {
		l.Info().Int("count", cnt).Str("coordinator", cord.Name()).Msg("Starting policy coordinator")
		err := cord.Run(ctx)
		if !errors.Is(err, context.Canceled) {
			l.Err(err).Msg("Policy coordinator failed and stopped")
			if errors.Is(sleep.WithContext(ctx, d), context.Canceled) {
				break
			}
		} else {
			break
		}
		cnt += 1
	}
}

func runCoordinatorOutput(ctx context.Context, cord Coordinator, bulker bulk.Bulk, l zerolog.Logger, policiesIndex string) {
	for {
		select {
		case p := <-cord.Output():
			s := l.With().Int64(dl.FieldRevisionIdx, p.RevisionIdx).Int64(dl.FieldCoordinatorIdx, p.CoordinatorIdx).Logger()
			_, err := dl.CreatePolicy(ctx, bulker, p, dl.WithIndexName(policiesIndex))
			if err != nil {
				s.Err(err).Msg("Policy coordinator failed to add a new policy revision")
			} else {
				s.Info().Int64("revision_id", p.RevisionIdx).Msg("Policy coordinator added a new policy revision")
			}
		case <-ctx.Done():
			return
		}
	}
}
