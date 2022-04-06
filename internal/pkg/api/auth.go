// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package api exposes fleet-server's API to agents.
package api

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
	ErrAPIKeyNotEnabled = errors.New("APIKey not enabled")
	ErrAgentCorrupted   = errors.New("agent record corrupted")
	ErrAgentInactive    = errors.New("agent inactive")
	ErrAgentIdentity    = errors.New("agent header contains wrong identifier")
)

// This authenticates that the provided API key exists and is enabled.
// WARNING: This does not validate that the api key is valid for the Fleet Domain.
// An additional check must be executed to validate it is not a random api key.
func authAPIKey(r *http.Request, bulker bulk.Bulk, c cache.Cache) (*apikey.ApiKey, error) {

	key, err := apikey.ExtractAPIKey(r)
	if err != nil {
		return nil, err
	}

	if c.ValidApiKey(*key) {
		return key, nil
	}

	reqID := r.Header.Get(logger.HeaderRequestID)

	start := time.Now()

	info, err := bulker.ApiKeyAuth(r.Context(), *key)

	if err != nil {
		log.Info().
			Err(err).
			Str(LogAPIKeyID, key.Id).
			Str(EcsHTTPRequestID, reqID).
			Int64(EcsEventDuration, time.Since(start).Nanoseconds()).
			Msg("ApiKey fail authentication")
		return nil, err
	}

	log.Trace().
		Str("id", key.Id).
		Str(EcsHTTPRequestID, reqID).
		Int64(EcsEventDuration, time.Since(start).Nanoseconds()).
		Str("userName", info.UserName).
		Strs("roles", info.Roles).
		Bool("enabled", info.Enabled).
		RawJSON("meta", info.Metadata).
		Msg("ApiKey authenticated")

	c.SetApiKey(*key, info.Enabled)
	if !info.Enabled {
		err = ErrAPIKeyNotEnabled
		log.Info().
			Err(err).
			Str("id", key.Id).
			Str(EcsHTTPRequestID, reqID).
			Int64(EcsEventDuration, time.Since(start).Nanoseconds()).
			Msg("ApiKey not enabled")
	}

	return key, err
}

func authAgent(r *http.Request, id *string, bulker bulk.Bulk, c cache.Cache) (*model.Agent, error) {
	start := time.Now()

	// authenticate
	key, err := authAPIKey(r, bulker, c)
	if err != nil {
		return nil, err
	}

	w := log.With().
		Str(LogAccessAPIKeyID, key.Id).
		Str(EcsHTTPRequestID, r.Header.Get(logger.HeaderRequestID))

	if id != nil {
		w = w.Str(LogAgentID, *id)
	}

	zlog := w.Logger()

	authTime := time.Now()

	if authTime.Sub(start) > time.Second {
		zlog.Debug().
			Int64(EcsEventDuration, authTime.Sub(start).Nanoseconds()).
			Msg("authApiKey slow")
	}

	agent, err := findAgentByAPIKeyID(r.Context(), bulker, key.Id)
	if err != nil {
		return nil, err
	}

	if agent.Agent == nil {
		zlog.Warn().
			Err(ErrAgentCorrupted).
			Msg("agent record does not contain required metadata section")
		return nil, ErrAgentCorrupted
	}

	findTime := time.Now()

	if findTime.Sub(authTime) > time.Second {
		zlog.Debug().
			Int64(EcsEventDuration, findTime.Sub(authTime).Nanoseconds()).
			Msg("findAgentByApiKeyId slow")
	}

	// validate that the Access ApiKey identifier stored in the agent's record
	// is in alignment when the authenticated key provided on this transaction
	if agent.AccessApiKeyId != key.Id {
		zlog.Warn().
			Err(ErrAgentCorrupted).
			Str("agent.AccessApiKeyId", agent.AccessApiKeyId).
			Msg("agent access ApiKey id mismatch agent record")
		return nil, ErrAgentCorrupted
	}

	// validate that the id in the header is equal to the agent id record
	if id != nil && *id != agent.Id {
		zlog.Warn().
			Err(ErrAgentIdentity).
			Str("agent.Id", agent.Id).
			Msg("agent id mismatch against http header")
		return nil, ErrAgentIdentity
	}

	// validate active, an api key can be valid for an inactive agent record
	// if it is in our cache and has not timed out.
	if !agent.Active {
		zlog.Info().
			Err(ErrAgentInactive).
			Msg("agent record inactive")

		// Update the cache to mark the api key id associated with this agent as not enabled
		c.SetApiKey(*key, false)
		return nil, ErrAgentInactive
	}

	return agent, nil
}
