// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package apikey

import (
	"context"
	"encoding/json"

	"github.com/elastic/go-elasticsearch/v7"
	"github.com/elastic/go-elasticsearch/v7/esapi"
	"github.com/pkg/errors"
)

type APIKeyMetadata struct {
	ID       string
	Metadata Metadata
}

func Read(ctx context.Context, client *elasticsearch.Client, id string) (*APIKeyMetadata, error) {

	opts := []func(*esapi.SecurityGetAPIKeyRequest){
		client.Security.GetAPIKey.WithContext(ctx),
		client.Security.GetAPIKey.WithID(id),
	}

	res, err := client.Security.GetAPIKey(
		opts...,
	)

	if err != nil {
		return nil, err
	}

	defer func() {
		_ = res.Body.Close()
	}()

	if res.IsError() {
		err = errors.Wrap(ErrAPIKeyNotFound, res.String())
		return nil, err
	}

	type APIKeyResponse struct {
		ID       string   `json:"id"`
		Metadata Metadata `json:"metadata"`
	}
	type GetAPIKeyResponse struct {
		APIKeys []APIKeyResponse `json:"api_keys"`
	}

	var resp GetAPIKeyResponse
	d := json.NewDecoder(res.Body)
	if err = d.Decode(&resp); err != nil {
		return nil, err
	}

	if len(resp.APIKeys) == 0 {
		return nil, ErrAPIKeyNotFound
	}

	first := resp.APIKeys[0]

	return &APIKeyMetadata{
		ID:       first.ID,
		Metadata: first.Metadata,
	}, nil
}
