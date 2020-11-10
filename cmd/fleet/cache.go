// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package main

import (
	"fleet/internal/pkg/apikey"
	"github.com/dgraph-io/ristretto"
	"github.com/rs/zerolog/log"
	"time"
)

type ApiKey = apikey.ApiKey
type SecurityInfo = apikey.SecurityInfo

var gCache Cache

func initGlobalCache() (err error) {
	gCache, err = NewCache()
	return err
}

type Cache struct {
	cache *ristretto.Cache
}

func NewCache() (Cache, error) {

	cfg := &ristretto.Config{
		NumCounters: 1000000,           // number of keys to track frequency of
		MaxCost:     100 * 1024 * 1024, // maximum cost of cache (100MB)
		BufferItems: 64,
	}

	cache, err := ristretto.NewCache(cfg)
	return Cache{cache}, err
}

func (c Cache) SetAction(id string, action Action, cost int64) {
	ok := c.cache.Set(id, action, cost)
	log.Trace().
		Bool("ok", ok).
		Str("id", id).
		Int64("cost", cost).
		Msg("Action cache SET")
}

func (c Cache) GetAction(id string) (Action, bool) {
	if v, ok := c.cache.Get(id); ok {
		log.Trace().Str("id", id).Msg("Action cache HIT")
		action, ok := v.(Action)

		if !ok {
			log.Error().Str("id", id).Msg("Action cache cast fail")
			return Action{}, false
		}
		return action, ok
	}

	log.Trace().Str("id", id).Msg("Action cache MISS")
	return Action{}, false
}

func (c Cache) SetApiKey(key ApiKey, ttl time.Duration) {
	cost := len(key.Id) + len(key.Key)
	ok := c.cache.SetWithTTL(key.Id, key.Key, int64(cost), ttl)
	log.Trace().
		Bool("ok", ok).
		Str("key", key.Id).
		Dur("ttl", ttl).
		Int("cost", cost).
		Msg("ApiKey cache SET")
}

func (c Cache) ValidApiKey(key ApiKey) bool {
	v, ok := c.cache.Get(key.Id)
	if ok {
		if v == key.Key {
			log.Trace().Str("id", key.Id).Msg("ApiKey cache HIT")
		} else {
			log.Trace().Str("id", key.Id).Msg("ApiKey cache MISMATCH")
			ok = false
		}
	} else {
		log.Trace().Str("id", key.Id).Msg("ApiKey cache MISS")
	}
	return ok
}

func (c Cache) GetEnrollmentApiKey(id string) (EnrollmentApiKey, bool) {
	scopedKey := "record:" + id
	if v, ok := c.cache.Get(scopedKey); ok {
		log.Trace().Str("id", id).Msg("Enrollment cache HIT")
		key, ok := v.(EnrollmentApiKey)

		if !ok {
			log.Error().Str("id", id).Msg("Enrollment cache cast fail")
			return EnrollmentApiKey{}, false
		}
		return key, ok
	}

	log.Trace().Str("id", id).Msg("EnrollmentApiKey cache MISS")
	return EnrollmentApiKey{}, false
}

func (c Cache) SetEnrollmentApiKey(id string, key EnrollmentApiKey, cost int64, ttl time.Duration) {
	scopedKey := "record:" + id
	ok := c.cache.SetWithTTL(scopedKey, key, cost, ttl)
	log.Trace().
		Bool("ok", ok).
		Str("id", id).
		Int64("cost", cost).
		Dur("ttl", ttl).
		Msg("EnrollmentApiKey cache SET")
}
