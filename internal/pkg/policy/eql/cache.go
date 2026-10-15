// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package eql

import "sync"

// maxCached bounds the parse cache; it is cleared when full.
const maxCached = 1 << 16

type parsed struct {
	n   node
	err error
}

// The same conditions are evaluated for every agent on a policy, so parse
// results are shared. Parsed trees are never mutated.
var parseCache = struct {
	sync.RWMutex
	m map[string]parsed
}{m: make(map[string]parsed)}

func parseCached(s string) (node, error) {
	parseCache.RLock()
	p, ok := parseCache.m[s]
	parseCache.RUnlock()
	if ok {
		return p.n, p.err
	}
	n, err := parse(s)
	parseCache.Lock()
	if len(parseCache.m) >= maxCached {
		clear(parseCache.m)
	}
	parseCache.m[s] = parsed{n: n, err: err}
	parseCache.Unlock()
	return n, err
}
