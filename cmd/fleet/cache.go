// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"fleet/internal/pkg/apikey"
	"fleet/internal/pkg/model"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/rs/zerolog/log"
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

func (c Cache) SetAction(id string, action model.Action, cost int64) {
	ok := c.cache.Set(id, action, cost)
	log.Trace().
		Bool("ok", ok).
		Str("id", id).
		Int64("cost", cost).
		Msg("Action cache SET")
}

func (c Cache) GetAction(id string) (model.Action, bool) {
	if v, ok := c.cache.Get(id); ok {
		log.Trace().Str("id", id).Msg("Action cache HIT")
		action, ok := v.(model.Action)

		if !ok {
			log.Error().Str("id", id).Msg("Action cache cast fail")
			return model.Action{}, false
		}
		return action, ok
	}

	log.Trace().Str("id", id).Msg("Action cache MISS")
	return model.Action{}, false
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

func (c Cache) GetEnrollmentApiKey(id string) (model.EnrollmentApiKey, bool) {
	scopedKey := "record:" + id
	if v, ok := c.cache.Get(scopedKey); ok {
		log.Trace().Str("id", id).Msg("Enrollment cache HIT")
		key, ok := v.(model.EnrollmentApiKey)

		if !ok {
			log.Error().Str("id", id).Msg("Enrollment cache cast fail")
			return model.EnrollmentApiKey{}, false
		}
		return key, ok
	}

	log.Trace().Str("id", id).Msg("EnrollmentApiKey cache MISS")
	return model.EnrollmentApiKey{}, false
}

func (c Cache) SetEnrollmentApiKey(id string, key model.EnrollmentApiKey, cost int64, ttl time.Duration) {
	scopedKey := "record:" + id
	ok := c.cache.SetWithTTL(scopedKey, key, cost, ttl)
	log.Trace().
		Bool("ok", ok).
		Str("id", id).
		Int64("cost", cost).
		Dur("ttl", ttl).
		Msg("EnrollmentApiKey cache SET")
}
