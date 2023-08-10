// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package bulk

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/elastic/go-elasticsearch/v8"
)

type ExtendedClient struct {
	*elasticsearch.Client
	Custom *ExtendedAPI
}

type ExtendedAPI struct {
	*elasticsearch.Client
}

// Read secret values with custom ES API added in Fleet ES plugin, there is no direct access to secrets index
// GET /_fleet/secret/secretId
func (c *ExtendedAPI) Read(ctx context.Context, secretID string) (*SecretResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "/_fleet/secret/"+secretID, nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if err != nil {
		return nil, err
	}

	res, err := c.Perform(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var secretResp SecretResponse

	err = json.NewDecoder(res.Body).Decode(&secretResp)
	if err != nil {
		return nil, err
	}
	return &secretResp, nil
}

type SecretResponse struct {
	Value string
}

func ReadSecret(ctx context.Context, client *elasticsearch.Client, secretID string) (string, error) {
	es := ExtendedClient{Client: client, Custom: &ExtendedAPI{client}}
	res, err := es.Custom.Read(ctx, secretID)
	if err != nil {
		return "", err
	}
	if res == nil {
		return "", nil
	}
	return (*res).Value, err
}
