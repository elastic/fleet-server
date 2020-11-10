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

package apikey

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
)

func Create(ctx context.Context, client *elasticsearch.Client, name, ttl string, roles []byte) (*ApiKey, error) {

	payload := struct {
		Name       string          `json:"name,omitempty"`
		Expiration string          `json:"expiration,omitempty"`
		Roles      json.RawMessage `json:"role_descriptors,omitempty"`
	}{
		name,
		ttl,
		roles,
	}

	body, err := json.Marshal(&payload)
	if err != nil {
		return nil, err
	}

	opts := []func(*esapi.SecurityCreateAPIKeyRequest){
		client.Security.CreateAPIKey.WithContext(ctx),
		client.Security.CreateAPIKey.WithRefresh("true"),
	}

	res, err := client.Security.CreateAPIKey(
		bytes.NewReader(body),
		opts...,
	)

	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("Fail CreateAPIKey: %s", res.String())
	}

	type APIKeyResponse struct {
		Id         string `json:"id"`
		Name       string `json:"name"`
		Expiration uint64 `json:"expiration"`
		ApiKey     string `json:"api_key"`
	}

	var resp APIKeyResponse
	d := json.NewDecoder(res.Body)
	if err = d.Decode(&resp); err != nil {
		return nil, err
	}

	key := ApiKey{
		Id:  resp.Id,
		Key: resp.ApiKey,
	}

	return &key, err
}
