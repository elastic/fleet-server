// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

type Runtime struct {
	GCPercent int `config:"gc_percent"`
	// set to math.MaxInt64 by default, setting to too low might result in the GC running almost continuously
	// see https://pkg.go.dev/runtime/debug#SetMemoryLimit
	MemoryLimit int64 `config:"memory_limit"`
}

func (r Runtime) InitDefaults() {
	//r.GCPercent = 0 // go will default it to zero
}
