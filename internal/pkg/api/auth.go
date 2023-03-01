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
	"github.com/elastic/fleet-server/v7/internal/pkg/model"

	"github.com/rs/zerolog/hlog"
	"go.elastic.co/apm/v2"
)

var (
	ErrAPIKeyNotEnabled = errors.New("APIKey not enabled")
	ErrAgentCorrupted   = errors.New("agent record corrupted")
	ErrAgentInactive    = errors.New("agent inactive")
	ErrAgentIdentity    = errors.New("agent header contains wrong identifier")
)

// authAPIKey authenticates the provided API key, it checks that the key exists and is enabled.
// WARNING: This does not validate that the api key is valid for the Fleet Domain.
// An additional check must be executed to validate it is not a random api key.
func authAPIKey(r *http.Request, bulker bulk.Bulk, c cache.Cache) (*apikey.APIKey, error) {
	span, ctx := apm.StartSpan(r.Context(), "authAPIKey", "auth")
	defer span.End()
	start := time.Now()

	key, err := apikey.ExtractAPIKey(r)
	if err != nil {
		return nil, err
	}

	if c.ValidAPIKey(*key) {
		span.Context.SetLabel("api_key_cache_hit", true)
		hlog.FromRequest(r).Debug().
			Str("id", key.ID).
			Int64(ECSEventDuration, time.Since(start).Nanoseconds()).
			Bool("fleet.apikey.cache_hit", true).
			Msg("ApiKey authenticated")
		return key, nil
	} else {
		span.Context.SetLabel("api_key_cache_hit", false)
	}

	info, err := bulker.APIKeyAuth(ctx, *key)

	if err != nil {
		hlog.FromRequest(r).Info().
			Err(err).
			Str(LogAPIKeyID, key.ID).
			Int64(ECSEventDuration, time.Since(start).Nanoseconds()).
			Msg("ApiKey fail authentication")
		return nil, err
	}

	hlog.FromRequest(r).Debug().
		Str("id", key.ID).
		Int64(ECSEventDuration, time.Since(start).Nanoseconds()).
		Str("userName", info.UserName).
		Strs("roles", info.Roles).
		Bool("enabled", info.Enabled).
		RawJSON("meta", info.Metadata).
		Bool("fleet.apikey.cache_hit", false).
		Msg("ApiKey authenticated")

	c.SetAPIKey(*key, info.Enabled)
	if !info.Enabled {
		err = ErrAPIKeyNotEnabled
		hlog.FromRequest(r).Info().
			Err(err).
			Str("id", key.ID).
			Int64(ECSEventDuration, time.Since(start).Nanoseconds()).
			Msg("ApiKey not enabled")
	}

	return key, err
}

// authAgent ensures that the requested API-Key is associated with the correct agent.
// If all succeeds, it returns the agent associated with id.
func authAgent(r *http.Request, id *string, bulker bulk.Bulk, c cache.Cache) (*model.Agent, error) {
	start := time.Now()

	// authenticate
	key, err := authAPIKey(r, bulker, c)
	if err != nil {
		return nil, err
	}

	w := hlog.FromRequest(r).With().
		Str(LogAccessAPIKeyID, key.ID)

	if id != nil {
		w = w.Str(LogAgentID, *id)
	}

	zlog := w.Logger()

	authTime := time.Now()

	if authTime.Sub(start) > time.Second {
		zlog.Debug().
			Int64(ECSEventDuration, authTime.Sub(start).Nanoseconds()).
			Msg("authApiKey slow")
	}

	agent, err := findAgentByAPIKeyID(r.Context(), bulker, key.ID)
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
			Int64(ECSEventDuration, findTime.Sub(authTime).Nanoseconds()).
			Msg("findAgentByApiKeyId slow")
	}

	// validate that the Access ApiKey identifier stored in the agent's record
	// is in alignment when the authenticated key provided on this transaction
	if agent.AccessAPIKeyID != key.ID {
		zlog.Warn().
			Err(ErrAgentCorrupted).
			Str("agent.AccessApiKeyId", agent.AccessAPIKeyID).
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
		c.SetAPIKey(*key, false)
		return nil, ErrAgentInactive
	}

	return agent, nil
}
