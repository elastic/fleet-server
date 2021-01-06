// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"errors"
	"net/http"
	"time"

	"fleet-server/internal/pkg/apikey"
	"fleet-server/internal/pkg/bulk"
	"fleet-server/internal/pkg/cache"
	"fleet-server/internal/pkg/model"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/rs/zerolog/log"
)

const (
	kAPIKeyTTL = 5 * time.Second
)

var ErrApiKeyNotEnabled = errors.New("APIKey not enabled")

func authApiKey(r *http.Request, client *elasticsearch.Client, c cache.Cache) (*apikey.ApiKey, error) {

	key, err := apikey.ExtractAPIKey(r)
	if err != nil {
		return nil, err
	}

	if c.ValidApiKey(*key) {
		return key, nil
	}

	start := time.Now()

	info, err := key.Authenticate(r.Context(), client)

	if err != nil {
		log.Error().
			Err(err).
			Dur("tdiff", time.Since(start)).
			Msg("ApiKey fail authentication")
		return nil, err
	}

	log.Trace().
		Str("id", key.Id).
		Dur("tdiff", time.Since(start)).
		Str("UserName", info.UserName).
		Strs("Roles", info.Roles).
		Bool("enabled", info.Enabled).
		RawJSON("meta", info.Metadata).
		Msg("ApiKey authenticated")

	if info.Enabled {
		c.SetApiKey(*key, kAPIKeyTTL)
	} else {
		err = ErrApiKeyNotEnabled
	}

	return key, err
}

func authAgent(r *http.Request, id string, bulker bulk.Bulk, c cache.Cache) (*model.Agent, error) {
	// authenticate
	key, err := authApiKey(r, bulker.Client(), c)
	if err != nil {
		return nil, err
	}

	agent, err := findAgentByApiKeyId(r.Context(), bulker, key.Id)
	if err != nil {
		return nil, err
	}

	// validate key alignment
	if agent.AccessApiKeyId != key.Id {
		log.Debug().
			Err(ErrAgentCorrupted).
			Interface("agent", &agent).
			Str("key.Id", key.Id).
			Msg("agent id mismatch")
		return nil, ErrAgentCorrupted
	}

	return agent, nil
}
