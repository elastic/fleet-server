// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package state wraps elastic-agent-client's unit.UpdateState rpc calls.
package state

import (
	"context"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/rs/zerolog"
)

// Reporter is interface that reports updated state on.
type Reporter interface {
	// UpdateState triggers updating the state.
	UpdateState(state client.UnitState, message string, payload map[string]interface{}) error
}

// Log will write state' to log.
type Log struct{}

// NewLog creates a Log.
func NewLog() *Log {
	return &Log{}
}

// UpdateState triggers updating the state.
func (l *Log) UpdateState(state client.UnitState, message string, _ map[string]interface{}) error {
	zerolog.Ctx(context.TODO()).Info().Str("state", state.String()).Msg(message)
	return nil
}

// Chained calls State on all the provided reporters in the provided order.
type Chained struct {
	reporters []Reporter
}

// NewChained creates a Chained with provided reporters.
func NewChained(reporters ...Reporter) *Chained {
	return &Chained{reporters}
}

// UpdateState triggers updating the state.
func (l *Chained) UpdateState(state client.UnitState, message string, payload map[string]interface{}) error {
	for _, reporter := range l.reporters {
		if err := reporter.UpdateState(state, message, payload); err != nil {
			return err
		}
	}
	return nil
}
