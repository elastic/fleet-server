// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package gc

import (
	"context"
	"errors"
	"time"

	"github.com/rs/zerolog"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"
	"github.com/elastic/fleet-server/v7/internal/pkg/secret"
)

const (
	defaultOutputSecretCandidateQueueSize = 10_000
	defaultOutputSecretGracePeriod        = 10 * time.Minute
	defaultOutputSecretCheckInterval      = time.Minute
	defaultOutputSecretConfirmationPeriod = 5 * time.Minute
	defaultOutputSecretOperationTimeout   = 30 * time.Second
	defaultOutputSecretMaxChecksPerRun    = 100
)

type outputSecretCandidateState struct {
	policy.OutputSecretCandidate
	createdAt           time.Time
	firstUnreferencedAt time.Time
}

// OrphanedOutputSecretReconciler conservatively removes output secrets that
// were retained after an ambiguous agent update failure but are not referenced
// by the resulting agent document.
//
// Candidates intentionally live only in memory. Losing one during a Fleet
// Server restart can leak a secret, but can never delete a secret still in use.
type OrphanedOutputSecretReconciler struct {
	bulker             bulk.Bulk
	candidates         chan policy.OutputSecretCandidate
	pending            map[string]*outputSecretCandidateState
	gracePeriod        time.Duration
	checkInterval      time.Duration
	confirmationPeriod time.Duration
	operationTimeout   time.Duration
	maxChecksPerRun    int
	now                func() time.Time
}

// NewOrphanedOutputSecretReconciler creates an in-memory candidate reconciler.
func NewOrphanedOutputSecretReconciler(bulker bulk.Bulk) *OrphanedOutputSecretReconciler {
	return &OrphanedOutputSecretReconciler{
		bulker:             bulker,
		candidates:         make(chan policy.OutputSecretCandidate, defaultOutputSecretCandidateQueueSize),
		pending:            make(map[string]*outputSecretCandidateState),
		gracePeriod:        defaultOutputSecretGracePeriod,
		checkInterval:      defaultOutputSecretCheckInterval,
		confirmationPeriod: defaultOutputSecretConfirmationPeriod,
		operationTimeout:   defaultOutputSecretOperationTimeout,
		maxChecksPerRun:    defaultOutputSecretMaxChecksPerRun,
		now:                time.Now,
	}
}

// Add queues a candidate without delaying the check-in request. A full queue
// fails safe by leaking the candidate rather than blocking or deleting it.
func (r *OrphanedOutputSecretReconciler) Add(candidate policy.OutputSecretCandidate) bool {
	select {
	case r.candidates <- candidate:
		return true
	default:
		return false
	}
}

// Run reconciles candidates until the Fleet Server context is cancelled.
func (r *OrphanedOutputSecretReconciler) Run(ctx context.Context) error {
	ticker := time.NewTicker(r.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case candidate := <-r.candidates:
			r.pending[candidate.SecretID] = &outputSecretCandidateState{
				OutputSecretCandidate: candidate,
				createdAt:             r.now(),
			}
		case <-ticker.C:
			r.reconcile(ctx)
		}
	}
}

func (r *OrphanedOutputSecretReconciler) reconcile(ctx context.Context) {
	now := r.now()
	checks := 0
	for secretID, candidate := range r.pending {
		if now.Sub(candidate.createdAt) < r.gracePeriod {
			continue
		}
		if checks >= r.maxChecksPerRun {
			return
		}
		checks++

		opCtx, cancel := context.WithTimeout(ctx, r.operationTimeout)
		agent, err := dl.GetAgent(opCtx, r.bulker, candidate.AgentID)
		cancel()
		if err != nil && !errors.Is(err, dl.ErrNotFound) {
			zerolog.Ctx(ctx).Warn().Err(err).
				Str("agent.id", candidate.AgentID).
				Str("fleet.policy.output.name", candidate.OutputName).
				Str("secret.id", candidate.SecretID).
				Msg("failed to inspect output secret reconciliation candidate")
			continue
		}

		if err == nil && outputSecretIsReferenced(&agent, candidate.OutputSecretCandidate) {
			delete(r.pending, secretID)
			continue
		}

		if candidate.firstUnreferencedAt.IsZero() {
			candidate.firstUnreferencedAt = now
			continue
		}
		if now.Sub(candidate.firstUnreferencedAt) < r.confirmationPeriod {
			continue
		}

		opCtx, cancel = context.WithTimeout(ctx, r.operationTimeout)
		err = r.bulker.DeleteSecret(opCtx, candidate.SecretID)
		cancel()
		if err != nil {
			zerolog.Ctx(ctx).Warn().Err(err).
				Str("agent.id", candidate.AgentID).
				Str("fleet.policy.output.name", candidate.OutputName).
				Str("secret.id", candidate.SecretID).
				Msg("failed to delete orphaned output secret candidate")
			continue
		}

		delete(r.pending, secretID)
		zerolog.Ctx(ctx).Info().
			Str("agent.id", candidate.AgentID).
			Str("fleet.policy.output.name", candidate.OutputName).
			Str("secret.id", candidate.SecretID).
			Msg("deleted orphaned output secret candidate")
	}
}

func outputSecretIsReferenced(agent *model.Agent, candidate policy.OutputSecretCandidate) bool {
	if agent.DefaultAPIKey == candidate.SecretRef {
		return true
	}
	for _, output := range agent.Outputs {
		if output.APIKey == candidate.SecretRef {
			return true
		}
		for _, retired := range output.ToRetireAPIKeyIds {
			if retired.SecretID == candidate.SecretID {
				return true
			}
		}
	}
	for _, retired := range agent.DefaultAPIKeyHistory {
		if retired.SecretID == candidate.SecretID {
			return true
		}
	}
	if secretID, ok := secret.ParseSecretReference(agent.DefaultAPIKey); ok {
		return secretID == candidate.SecretID
	}
	return false
}
