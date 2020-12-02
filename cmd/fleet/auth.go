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

package fleet

import (
	"errors"
	"net/http"
	"time"

	"fleet/internal/pkg/apikey"
	"fleet/internal/pkg/saved"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/rs/zerolog/log"
)

const (
	kAPIKeyTTL = 5 * time.Second
)

var ErrApiKeyNotEnabled = errors.New("APIKey not enabled")

func authApiKey(r *http.Request, client *elasticsearch.Client) (*apikey.ApiKey, error) {

	key, err := apikey.ExtractAPIKey(r)
	if err != nil {
		return nil, err
	}

	if gCache.ValidApiKey(*key) {
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
		gCache.SetApiKey(*key, kAPIKeyTTL)
	} else {
		err = ErrApiKeyNotEnabled
	}

	return key, err
}

func authAgent(r *http.Request, id string, sv saved.CRUD) (*Agent, error) {
	// authenticate
	key, err := authApiKey(r, sv.Client())
	if err != nil {
		return nil, err
	}

	agent, err := findAgentByApiKeyId(r.Context(), sv, key.Id)
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
