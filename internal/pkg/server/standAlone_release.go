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
