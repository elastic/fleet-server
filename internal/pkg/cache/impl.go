// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cache

import (
	"time"
)

type CacheImpl interface {
	Get(key interface{}) (interface{}, bool)
	Set(key, value interface{}, cost int64) bool
	SetWithTTL(key, value interface{}, cost int64, ttl time.Duration) bool
	Close()
}
