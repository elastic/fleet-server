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

	"github.com/elastic/go-elasticsearch/v7"
	"github.com/rs/zerolog/log"
)

const (
	kAPIKeyTTL = 5 * time.Second
)

var (
	ErrApiKeyNotEnabled = errors.New("APIKey not enabled")
	ErrAgentCorrupted   = errors.New("agent record corrupted")
)

// This authenticates that the provided API key exists and is enabled.
// WARNING: This does not validate that the api key is valid for the Fleet Domain.
// An additional check must be executed to validate it is not a random api key.
func authApiKey(r *http.Request, client *elasticsearch.Client, c cache.Cache) (*apikey.ApiKey, error) {

	key, err := apikey.ExtractAPIKey(r)
	if err != nil {
		return nil, err
	}

	if c.ValidApiKey(*key) {
		return key, nil
	}

	reqId := r.Header.Get(logger.HeaderRequestID)

	start := time.Now()

	info, err := key.Authenticate(r.Context(), client)

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

	if info.Enabled {
		c.SetApiKey(*key, kAPIKeyTTL)
	} else {
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
	key, err := authApiKey(r, bulker.Client(), c)
	if err != nil {
		return nil, err
	}

	authTime := time.Now()

	agent, err := findAgentByApiKeyId(r.Context(), bulker, key.Id)
	if err != nil {
		return nil, err
	}

	findTime := time.Now()

	// TOOD: Remove temporary log msg to diag roundtrip speed issue on auth
	if findTime.Sub(start) > time.Second*5 {
		reqId := r.Header.Get(logger.HeaderRequestID)

		zlog := log.With().
			Str("agentId", id).
			Str(EcsHttpRequestId, reqId).
			Logger()

		zlog.Debug().
			Int64(EcsEventDuration, authTime.Sub(start).Nanoseconds()).
			Msg("authApiKey slow")

		zlog.Debug().
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

	return agent, nil
}
