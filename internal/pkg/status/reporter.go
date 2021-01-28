// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package status

import (
	"github.com/rs/zerolog/log"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
)

// Reporter is interface that reports updated status on.
type Reporter interface {
	// Status triggers updating the status.
	Status(status proto.StateObserved_Status, message string, payload map[string]interface{}) error
}

// Log logs the reported status.
type Log struct{}

// NewLog creates a LogStatus.
func NewLog() *Log {
	return &Log{}
}

// Status triggers updating the status.
func (l *Log) Status(status proto.StateObserved_Status, message string, payload map[string]interface{}) error {
	log.Info().Str("status", status.String()).Fields(map[string]interface{}{
		"payload": payload,
	}).Msg(message)
	return nil
}

// Chained calls Status on all the provided reporters in the provided order.
type Chained struct {
	reporters []Reporter
}

// NewChained creates a Chained with provided reporters.
func NewChained(reporters ...Reporter) *Chained {
	return &Chained{reporters}
}

// Status triggers updating the status.
func (l *Chained) Status(status proto.StateObserved_Status, message string, payload map[string]interface{}) error {
	for _, reporter := range l.reporters {
		if err := reporter.Status(status, message, payload); err != nil {
			return err
		}
	}
	return nil
}
