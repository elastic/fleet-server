// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cache

import (
	"fmt"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/rs/zerolog/log"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

type ApiKey = apikey.ApiKey
type SecurityInfo = apikey.SecurityInfo

type Cache struct {
	cache *ristretto.Cache
}

type actionCache struct {
	actionId   string
	actionType string
}

// New creates a new cache.
func New() (Cache, error) {
	cfg := &ristretto.Config{
		NumCounters: 1000000,           // number of keys to track frequency of
		MaxCost:     100 * 1024 * 1024, // maximum cost of cache (100MB)
		BufferItems: 64,
	}

	cache, err := ristretto.NewCache(cfg)
	return Cache{cache}, err
}

// SetAction sets an action in the cache.
//
// This will only cache the action ID and action Type. So `GetAction` will only
// return a `model.Action` with `ActionId` and `Type` set.
func (c Cache) SetAction(action model.Action) {
	scopedKey := "action:" + action.ActionId
	v := actionCache{
		actionId:   action.ActionId,
		actionType: action.Type,
	}
	cost := len(action.ActionId) + len(action.Type)
	ok := c.cache.Set(scopedKey, v, int64(cost))
	log.Trace().
		Bool("ok", ok).
		Str("id", action.ActionId).
		Int("cost", cost).
		Msg("Action cache SET")
}

// GetAction returns an action from the cache.
//
// This will only return a `model.Action` with the action ID and action Type set.
// This is because `SetAction` So `GetAction` will only cache the action ID and action Type.
func (c Cache) GetAction(id string) (model.Action, bool) {
	scopedKey := "action:" + id
	if v, ok := c.cache.Get(scopedKey); ok {
		log.Trace().Str("id", id).Msg("Action cache HIT")
		action, ok := v.(actionCache)
		if !ok {
			log.Error().Str("id", id).Msg("Action cache cast fail")
			return model.Action{}, false
		}
		return model.Action{
			ActionId: action.actionId,
			Type:     action.actionType,
		}, ok
	}

	log.Trace().Str("id", id).Msg("Action cache MISS")
	return model.Action{}, false
}

// SetApiKey sets the API key in the cache.
func (c Cache) SetApiKey(key ApiKey, ttl time.Duration) {
	scopedKey := "api:" + key.Id
	cost := len(scopedKey) + len(key.Key)
	ok := c.cache.SetWithTTL(scopedKey, key.Key, int64(cost), ttl)
	log.Trace().
		Bool("ok", ok).
		Str("key", key.Id).
		Dur("ttl", ttl).
		Int("cost", cost).
		Msg("ApiKey cache SET")
}

// ValidApiKey returns true if the ApiKey is valid (aka. also present in cache).
func (c Cache) ValidApiKey(key ApiKey) bool {
	scopedKey := "api:" + key.Id
	v, ok := c.cache.Get(scopedKey)
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

// GetEnrollmentApiKey returns the enrollment API key by ID.
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

// SetEnrollmentApiKey adds the enrollment API key into the cache.
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

func makeArtifactKey(ident, sha2 string) string {
	return fmt.Sprintf("artifact:%s:%s", ident, sha2)
}

func (c Cache) GetArtifact(ident, sha2 string) (model.Artifact, bool) {
	scopedKey := makeArtifactKey(ident, sha2)
	if v, ok := c.cache.Get(scopedKey); ok {
		log.Trace().Str("key", scopedKey).Msg("Artifact cache HIT")
		key, ok := v.(model.Artifact)

		if !ok {
			log.Error().Str("sha2", sha2).Msg("Artifact cache cast fail")
			return model.Artifact{}, false
		}
		return key, ok
	}

	log.Trace().Str("key", scopedKey).Msg("Artifact cache MISS")
	return model.Artifact{}, false
}

// TODO: strip body and spool to on disk cache if larger than a size threshold
func (c Cache) SetArtifact(artifact model.Artifact, ttl time.Duration) {
	scopedKey := makeArtifactKey(artifact.Identifier, artifact.DecodedSha256)
	cost := int64(len(artifact.Body))
	ok := c.cache.SetWithTTL(scopedKey, artifact, cost, ttl)
	log.Trace().
		Bool("ok", ok).
		Str("key", scopedKey).
		Int64("cost", cost).
		Dur("ttl", ttl).
		Msg("Artifact cache SET")
}
