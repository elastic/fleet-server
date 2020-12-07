// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package reload

import (
	"context"

	"fleet/internal/pkg/config"
)

// Reloadable interface that ensures that a manager can be reloaded with updated config.
type Reloadable interface {
	// Reload should reload the configuration for the manager.
	//
	// It is up to the manager to verify if the change even affected the manager. If not
	// the manager should do nothing when Reload is called.
	Reload(context.Context, *config.Config) error
}

type reloadManager struct {
	managers []Reloadable
}

// NewReloadManager creates a new manager to handle calling reload.
func NewReloadManager(managers ...Reloadable) Reloadable {
	return &reloadManager{
		managers: managers,
	}
}

// Reload should reload the configuration for all the managers.
func (r *reloadManager) Reload(ctx context.Context, config *config.Config) error {
	for _, manager := range r.managers {
		if err := manager.Reload(ctx, config); err != nil {
			return err
		}
	}
	return nil
}
