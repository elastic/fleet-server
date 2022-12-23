// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !dev

package server

import (
	"context"

	"github.com/elastic/fleet-server/v7/internal/pkg/api"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"
)

// Run the SelfMonitor synchronously
func (f *Fleet) standAloneSetup(ctx context.Context, _ bulk.Bulk, sm policy.SelfMonitor, _, _ string) (*model.Agent, error) {
	return nil, sm.Run(ctx)
}

// nop
func (f *Fleet) standAloneCheckin(_ *model.Agent, _ *api.CheckinT) runFunc {
	return func(_ context.Context) error {
		return nil
	}
}
