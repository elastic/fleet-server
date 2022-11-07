// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package server defines the fleet-server instance.
package server

import (
	"context"
)

// Server defines the interface to run the service instance.
type Server interface {
	Run(context.Context) error
}
