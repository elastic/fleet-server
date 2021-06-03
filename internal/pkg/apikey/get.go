// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package apikey

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/elastic/go-elasticsearch/v7"
	"github.com/elastic/go-elasticsearch/v7/esapi"
)

type ApiKeyMetadata struct {
	Id       string
	Metadata Metadata
}

func Get(ctx context.Context, client *elasticsearch.Client, id string) (apiKey ApiKeyMetadata, err error) {

	opts := []func(*esapi.SecurityGetAPIKeyRequest){
		client.Security.GetAPIKey.WithContext(ctx),
		client.Security.GetAPIKey.WithID(id),
	}

	res, err := client.Security.GetAPIKey(
		opts...,
	)

	if err != nil {
		return
	}

	defer res.Body.Close()

	if res.IsError() {
		return apiKey, fmt.Errorf("fail GetAPIKey: %s, %w", res.String(), ErrApiKeyNotFound)
	}

	type APIKeyResponse struct {
		Id       string   `json:"id"`
		Metadata Metadata `json:"metadata"`
	}
	type GetAPIKeyResponse struct {
		ApiKeys []APIKeyResponse `json:"api_keys"`
	}

	var resp GetAPIKeyResponse
	d := json.NewDecoder(res.Body)
	if err = d.Decode(&resp); err != nil {
		return
	}

	if len(resp.ApiKeys) == 0 {
		return apiKey, ErrApiKeyNotFound
	}

	first := resp.ApiKeys[0]

	return ApiKeyMetadata{
		Id:       first.Id,
		Metadata: first.Metadata,
	}, nil
}
