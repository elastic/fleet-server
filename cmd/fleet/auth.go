// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"errors"
	"net/http"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"

	"github.com/rs/zerolog/log"
)

var (
	ErrApiKeyNotEnabled = errors.New("APIKey not enabled")
	ErrAgentCorrupted   = errors.New("agent record corrupted")
	ErrAgentInactive    = errors.New("agent inactive")
)

// This authenticates that the provided API key exists and is enabled.
// WARNING: This does not validate that the api key is valid for the Fleet Domain.
// An additional check must be executed to validate it is not a random api key.
func authApiKey(r *http.Request, bulker bulk.Bulk, c cache.Cache) (*apikey.ApiKey, error) {

	key, err := apikey.ExtractAPIKey(r)
	if err != nil {
		return nil, err
	}

	if c.ValidApiKey(*key) {
		return key, nil
	}

	reqId := r.Header.Get(logger.HeaderRequestID)

	start := time.Now()

	info, err := bulker.ApiKeyAuth(r.Context(), *key)

	if err != nil {
		log.Info().
			Err(err).
			Str("id", key.Id).
			Str(EcsHttpRequestId, reqId).
			Int64(EcsEventDuration, time.Since(start).Nanoseconds()).
			Msg("ApiKey fail authentication")
		return nil, err
	}

	log.Trace().
		Str("id", key.Id).
		Str(EcsHttpRequestId, reqId).
		Int64(EcsEventDuration, time.Since(start).Nanoseconds()).
		Str("userName", info.UserName).
		Strs("roles", info.Roles).
		Bool("enabled", info.Enabled).
		RawJSON("meta", info.Metadata).
		Msg("ApiKey authenticated")

	c.SetApiKey(*key, info.Enabled)
	if !info.Enabled {
		err = ErrApiKeyNotEnabled
		log.Info().
			Err(err).
			Str("id", key.Id).
			Str(EcsHttpRequestId, reqId).
			Int64(EcsEventDuration, time.Since(start).Nanoseconds()).
			Msg("ApiKey not enabled")
	}

	return key, err
}

func authAgent(r *http.Request, id string, bulker bulk.Bulk, c cache.Cache) (*model.Agent, error) {
	start := time.Now()

	// authenticate
	key, err := authApiKey(r, bulker, c)
	if err != nil {
		return nil, err
	}

	authTime := time.Now()

	if authTime.Sub(start) > time.Second {
		log.Debug().
			Str("agentId", id).
			Str(EcsHttpRequestId, r.Header.Get(logger.HeaderRequestID)).
			Int64(EcsEventDuration, authTime.Sub(start).Nanoseconds()).
			Msg("authApiKey slow")
	}

	agent, err := findAgentByApiKeyId(r.Context(), bulker, key.Id)
	if err != nil {
		return nil, err
	}

	findTime := time.Now()

	if findTime.Sub(authTime) > time.Second {
		log.Debug().
			Str("agentId", id).
			Str(EcsHttpRequestId, r.Header.Get(logger.HeaderRequestID)).
			Int64(EcsEventDuration, findTime.Sub(authTime).Nanoseconds()).
			Msg("findAgentByApiKeyId slow")
	}

	// validate key alignment
	if agent.AccessApiKeyId != key.Id {
		log.Info().
			Err(ErrAgentCorrupted).
			Interface("agent", &agent).
			Str("key.Id", key.Id).
			Msg("agent API key id mismatch agent record")
		return nil, ErrAgentCorrupted
	}

	// validate active, an api key can be valid for an inactive agent record
	// if it is in our cache and has not timed out.
	if !agent.Active {
		log.Info().
			Err(ErrAgentInactive).
			Str("agentId", id).
			Str(EcsHttpRequestId, r.Header.Get(logger.HeaderRequestID)).
			Msg("agent record inactive")

		// Update the cache to mark the api key id associated with this agent as not enabled
		c.SetApiKey(*key, false)
		return nil, ErrAgentInactive
	}

	return agent, nil
}
