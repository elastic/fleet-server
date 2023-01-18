// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package cache implements an in-memory cache used to track API keys, actions, and artifacts.
package cache

import (
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/uploader/upload"
)

type Cache interface {
	Reconfigure(config.Cache) error

	SetAction(model.Action)
	GetAction(id string) (model.Action, bool)

	SetAPIKey(key APIKey, enabled bool)
	ValidAPIKey(key APIKey) bool

	SetEnrollmentAPIKey(id string, key model.EnrollmentAPIKey, cost int64)
	GetEnrollmentAPIKey(id string) (model.EnrollmentAPIKey, bool)

	SetArtifact(artifact model.Artifact)
	GetArtifact(ident, sha2 string) (model.Artifact, bool)

	SetUpload(id string, info upload.Info)
	GetUpload(id string) (upload.Info, bool)
}

type APIKey = apikey.APIKey
type SecurityInfo = apikey.SecurityInfo

type CacheT struct {
	cache Cacher
	cfg   config.Cache
	mut   sync.RWMutex
}

type actionCache struct {
	actionID   string
	actionType string
}

// New creates a new cache.
func New(cfg config.Cache) (*CacheT, error) {
	cache, err := newCache(cfg)
	if err != nil {
		return nil, err
	}

	c := CacheT{
		cache: cache,
		cfg:   cfg,
	}

	return &c, nil
}

// Reconfigure will drop cache
func (c *CacheT) Reconfigure(cfg config.Cache) error {
	c.mut.Lock()
	defer c.mut.Unlock()

	cache, err := newCache(cfg)
	if err != nil {
		return err
	}

	// Close down previous cache
	c.cache.Close()

	// And assign new one
	c.cfg = cfg
	c.cache = cache
	return nil
}

// SetAction sets an action in the cache.
//
// This will only cache the action ID and action Type. So `GetAction` will only
// return a `model.Action` with `ActionId` and `Type` set.
func (c *CacheT) SetAction(action model.Action) {
	c.mut.RLock()
	defer c.mut.RUnlock()

	scopedKey := "action:" + action.ActionID
	v := actionCache{
		actionID:   action.ActionID,
		actionType: action.Type,
	}
	cost := len(action.ActionID) + len(action.Type)
	ttl := c.cfg.ActionTTL
	ok := c.cache.SetWithTTL(scopedKey, v, int64(cost), ttl)
	log.Trace().
		Bool("ok", ok).
		Str("id", action.ActionID).
		Int("cost", cost).
		Msg("Action cache SET")
}

// GetAction returns an action from the cache.
//
// This will only return a `model.Action` with the action ID and action Type set.
// This is because `SetAction` So `GetAction` will only cache the action ID and action Type.
func (c *CacheT) GetAction(id string) (model.Action, bool) {
	c.mut.RLock()
	defer c.mut.RUnlock()

	scopedKey := "action:" + id
	if v, ok := c.cache.Get(scopedKey); ok {
		log.Trace().Str("id", id).Msg("Action cache HIT")
		action, ok := v.(actionCache)
		if !ok {
			log.Error().Str("id", id).Msg("Action cache cast fail")
			return model.Action{}, false
		}
		return model.Action{
			ActionID: action.actionID,
			Type:     action.actionType,
		}, ok
	}

	log.Trace().Str("id", id).Msg("Action cache MISS")
	return model.Action{}, false
}

// SetAPIKey sets the API key in the cache.
func (c *CacheT) SetAPIKey(key APIKey, enabled bool) {
	c.mut.RLock()
	defer c.mut.RUnlock()

	scopedKey := "api:" + key.ID

	// Use the valid key as the payload of the record;
	// If caller has marked key as not enabled, use empty string.
	val := key.Key
	if !enabled {
		val = ""
	}

	// If enabled, jitter allows us to randomize the expiration of the artifact
	// across time, which is helpful if a bunch of agents came on at the same time,
	// say during a network restoration. With some jitter, we avoid having to
	// revalidate the API Keys all at the same time, which we know causes load on Elastic.
	ttl := c.cfg.APIKeyTTL
	if c.cfg.APIKeyJitter != 0 {
		jitter := time.Duration(rand.Int63n(int64(c.cfg.APIKeyJitter))) //nolint:gosec // used to generate a jitter offset value
		if jitter < ttl {
			ttl = ttl - jitter
		}
	}

	cost := len(scopedKey) + len(val)
	ok := c.cache.SetWithTTL(scopedKey, val, int64(cost), ttl)
	log.Trace().
		Bool("ok", ok).
		Bool("enabled", enabled).
		Str("key", key.ID).
		Dur("ttl", ttl).
		Int("cost", cost).
		Msg("ApiKey cache SET")
}

// ValidAPIKey returns true if the ApiKey is valid (aka. also present in cache).
func (c *CacheT) ValidAPIKey(key APIKey) bool {
	c.mut.RLock()
	defer c.mut.RUnlock()

	scopedKey := "api:" + key.ID
	v, ok := c.cache.Get(scopedKey)
	if ok {
		switch v {
		case "":
			log.Trace().Str("id", key.ID).Msg("ApiKey cache HIT on disabled KEY")
		case key.Key:
			log.Trace().Str("id", key.ID).Msg("ApiKey cache HIT")
		default:
			log.Trace().Str("id", key.ID).Msg("ApiKey cache MISMATCH")
			ok = false
		}
	} else {
		log.Trace().Str("id", key.ID).Msg("ApiKey cache MISS")
	}
	return ok
}

// GetEnrollmentAPIKey returns the enrollment API key by ID.
func (c *CacheT) GetEnrollmentAPIKey(id string) (model.EnrollmentAPIKey, bool) { //nolint:dupl // similar getters to support strong typing
	c.mut.RLock()
	defer c.mut.RUnlock()

	scopedKey := "record:" + id
	if v, ok := c.cache.Get(scopedKey); ok {
		log.Trace().Str("id", id).Msg("Enrollment cache HIT")
		key, ok := v.(model.EnrollmentAPIKey)

		if !ok {
			log.Error().Str("id", id).Msg("Enrollment cache cast fail")
			return model.EnrollmentAPIKey{}, false
		}
		return key, ok
	}

	log.Trace().Str("id", id).Msg("EnrollmentApiKey cache MISS")
	return model.EnrollmentAPIKey{}, false
}

// SetEnrollmentAPIKey adds the enrollment API key into the cache.
func (c *CacheT) SetEnrollmentAPIKey(id string, key model.EnrollmentAPIKey, cost int64) {
	c.mut.RLock()
	defer c.mut.RUnlock()

	scopedKey := "record:" + id
	ttl := c.cfg.EnrollKeyTTL
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

func (c *CacheT) GetArtifact(ident, sha2 string) (model.Artifact, bool) {
	c.mut.RLock()
	defer c.mut.RUnlock()

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

// SetArtifact will set the cached artifact
// TODO: strip body and spool to on disk cache if larger than a size threshold
func (c *CacheT) SetArtifact(artifact model.Artifact) {
	c.mut.RLock()
	defer c.mut.RUnlock()

	scopedKey := makeArtifactKey(artifact.Identifier, artifact.DecodedSha256)
	cost := int64(len(artifact.Body))
	ttl := c.cfg.ArtifactTTL

	ok := c.cache.SetWithTTL(scopedKey, artifact, cost, ttl)
	log.Trace().
		Bool("ok", ok).
		Str("key", scopedKey).
		Int64("cost", cost).
		Dur("ttl", ttl).
		Msg("Artifact cache SET")
}

func (c *CacheT) SetUpload(id string, info upload.Info) {
	c.mut.RLock()
	defer c.mut.RUnlock()

	scopedKey := "upload:" + id
	ttl := time.Hour / 2 // @todo: add to configurable
	cost := int64(len(info.ID) + len(info.DocID) + len(info.ActionID) + len(info.AgentID) + len(info.Source) + len(info.Status) + 8*4)
	ok := c.cache.SetWithTTL(scopedKey, info, cost, ttl)
	log.Trace().
		Bool("ok", ok).
		Str("id", id).
		Int64("cost", cost).
		Dur("ttl", ttl).
		Msg("Upload info cache SET")
}
func (c *CacheT) GetUpload(id string) (upload.Info, bool) { //nolint:dupl // a little repetition to support strong typing
	c.mut.RLock()
	defer c.mut.RUnlock()

	scopedKey := "upload:" + id
	if v, ok := c.cache.Get(scopedKey); ok {
		log.Trace().Str("id", id).Msg("upload info cache HIT")
		key, ok := v.(upload.Info)
		if !ok {
			log.Error().Str("id", id).Msg("upload info cache cast fail")
			return upload.Info{}, false
		}
		return key, ok
	}

	log.Trace().Str("id", id).Msg("upload info cache MISS")
	return upload.Info{}, false
}
