// Package server defines the fleet-server instance.
package server

import (
	"context"
)

// Server defines the interface to run the service instance.
type Server interface {
	Run(context.Context) error
}
