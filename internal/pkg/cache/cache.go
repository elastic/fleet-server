// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cache

import (
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

type Cache interface {
	Reconfigure(Config) error

	SetAction(model.Action)
	GetAction(id string) (model.Action, bool)

	SetApiKey(key ApiKey, enabled bool)
	ValidApiKey(key ApiKey) bool

	SetEnrollmentApiKey(id string, key model.EnrollmentApiKey, cost int64)
	GetEnrollmentApiKey(id string) (model.EnrollmentApiKey, bool)

	SetArtifact(artifact model.Artifact)
	GetArtifact(ident, sha2 string) (model.Artifact, bool)
}

type ApiKey = apikey.ApiKey
type SecurityInfo = apikey.SecurityInfo

type CacheT struct {
	cache *ristretto.Cache
	cfg   Config
	mut   sync.RWMutex
}

type Config struct {
	NumCounters  int64 // number of keys to track frequency of
	MaxCost      int64 // maximum cost of cache in 'cost' units
	ActionTTL    time.Duration
	ApiKeyTTL    time.Duration
	EnrollKeyTTL time.Duration
	ArtifactTTL  time.Duration
	ApiKeyJitter time.Duration
}

func (c *Config) MarshalZerologObject(e *zerolog.Event) {
	e.Int64("numCounters", c.NumCounters)
	e.Int64("maxCost", c.MaxCost)
	e.Dur("actionTTL", c.ActionTTL)
	e.Dur("enrollTTL", c.EnrollKeyTTL)
	e.Dur("artifactTTL", c.ArtifactTTL)
	e.Dur("apiKeyTTL", c.ApiKeyTTL)
	e.Dur("apiKeyJitter", c.ApiKeyJitter)
}

type actionCache struct {
	actionId   string
	actionType string
}

// New creates a new cache.
func New(cfg Config) (*CacheT, error) {
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

func newCache(cfg Config) (*ristretto.Cache, error) {
	rcfg := &ristretto.Config{
		NumCounters: cfg.NumCounters,
		MaxCost:     cfg.MaxCost,
		BufferItems: 64,
	}

	return ristretto.NewCache(rcfg)
}

// Reconfigure will drop cache
func (c *CacheT) Reconfigure(cfg Config) error {
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

	scopedKey := "action:" + action.ActionId
	v := actionCache{
		actionId:   action.ActionId,
		actionType: action.Type,
	}
	cost := len(action.ActionId) + len(action.Type)
	ttl := c.cfg.ActionTTL
	ok := c.cache.SetWithTTL(scopedKey, v, int64(cost), ttl)
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
			ActionId: action.actionId,
			Type:     action.actionType,
		}, ok
	}

	log.Trace().Str("id", id).Msg("Action cache MISS")
	return model.Action{}, false
}

// SetApiKey sets the API key in the cache.
func (c *CacheT) SetApiKey(key ApiKey, enabled bool) {
	c.mut.RLock()
	defer c.mut.RUnlock()

	scopedKey := "api:" + key.Id

	// Use the valid key as the payload of the record;
	// If caller has marked key as not enabled, use empty string.
	val := key.Key
	if !enabled {
		val = ""
	}

	// If enabled, jitter allows us to randomize the expirtion of the artifact
	// across time, which is helpful if a bunch of agents came on at the same time,
	// say during a network restoration.  With some jitter, we avoid having to
	// revalidate  the API Keys all at the same time, which we know causes load on Elastic.
	ttl := c.cfg.ApiKeyTTL
	if c.cfg.ApiKeyJitter != 0 {
		jitter := time.Duration(rand.Int63n(int64(c.cfg.ApiKeyJitter)))
		if jitter < ttl {
			ttl = ttl - jitter
		}
	}

	cost := len(scopedKey) + len(val)
	ok := c.cache.SetWithTTL(scopedKey, val, int64(cost), ttl)
	log.Trace().
		Bool("ok", ok).
		Bool("enabled", enabled).
		Str("key", key.Id).
		Dur("ttl", ttl).
		Int("cost", cost).
		Msg("ApiKey cache SET")
}

// ValidApiKey returns true if the ApiKey is valid (aka. also present in cache).
func (c *CacheT) ValidApiKey(key ApiKey) bool {
	c.mut.RLock()
	defer c.mut.RUnlock()

	scopedKey := "api:" + key.Id
	v, ok := c.cache.Get(scopedKey)
	if ok {
		switch v {
		case "":
			log.Trace().Str("id", key.Id).Msg("ApiKey cache HIT on disabled KEY")
		case key.Key:
			log.Trace().Str("id", key.Id).Msg("ApiKey cache HIT")
		default:
			log.Trace().Str("id", key.Id).Msg("ApiKey cache MISMATCH")
			ok = false
		}
	} else {
		log.Trace().Str("id", key.Id).Msg("ApiKey cache MISS")
	}
	return ok
}

// GetEnrollmentApiKey returns the enrollment API key by ID.
func (c *CacheT) GetEnrollmentApiKey(id string) (model.EnrollmentApiKey, bool) {
	c.mut.RLock()
	defer c.mut.RUnlock()

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
func (c *CacheT) SetEnrollmentApiKey(id string, key model.EnrollmentApiKey, cost int64) {
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
