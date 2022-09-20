// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package apikey

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/elastic/go-elasticsearch/v7"
	"github.com/elastic/go-elasticsearch/v7/esapi"
)

// Create generates a new APIKey in Elasticsearch using the given client.
func Create(ctx context.Context, client *elasticsearch.Client, name, ttl, refresh string, roles []byte, meta interface{}) (*APIKey, error) {
	payload := struct {
		Name       string          `json:"name,omitempty"`
		Expiration string          `json:"expiration,omitempty"`
		Roles      json.RawMessage `json:"role_descriptors,omitempty"`
		Metadata   interface{}     `json:"metadata"`
	}{
		Name:       name,
		Expiration: ttl,
		Roles:      roles,
		Metadata:   meta,
	}

	body, err := json.Marshal(&payload)
	if err != nil {
		return nil, err
	}

	opts := []func(*esapi.SecurityCreateAPIKeyRequest){
		client.Security.CreateAPIKey.WithContext(ctx),
		client.Security.CreateAPIKey.WithRefresh(refresh),
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
		return nil, fmt.Errorf("fail CreateAPIKey: %s", res.String())
	}

	type APIKeyResponse struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Expiration uint64 `json:"expiration"`
		APIKey     string `json:"api_key"`
	}

	var resp APIKeyResponse
	d := json.NewDecoder(res.Body)
	if err = d.Decode(&resp); err != nil {
		return nil, err
	}

	key := APIKey{
		ID:  resp.ID,
		Key: resp.APIKey,
	}

	return &key, err
}
