// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package config

type Runtime struct {
	// GCPercent sets GOGC. 0 keeps the GOGC of the Go runtime, which is 100 by default.
	// see https://pkg.go.dev/runtime/debug#SetGCPercent
	GCPercent int `config:"gc_percent"`
	// set to math.MaxInt64 by default, setting to too low might result in the GC running almost continuously
	// see https://pkg.go.dev/runtime/debug#SetMemoryLimit
	MemoryLimit int64 `config:"memory_limit"`
}

// InitDefaults keeps GCPercent and MemoryLimit at 0 so that the Go runtime values apply.
func (r Runtime) InitDefaults() {}
