// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package bulk

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/elastic/go-elasticsearch/v8"
	"go.elastic.co/apm/v2"
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

// Write stores a secret value via the Fleet ES plugin secrets API and returns the assigned secret ID.
// POST /_fleet/secret
func (c *ExtendedAPI) Write(ctx context.Context, value string) (string, error) {
	body, err := json.Marshal(struct {
		Value string `json:"value"`
	}{Value: value})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "/_fleet/secret", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	res, err := c.Perform(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	var resp struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		return "", err
	}
	return resp.ID, nil
}

type SecretResponse struct {
	Value string
}

func ReadSecret(ctx context.Context, client *elasticsearch.Client, secretID string) (string, error) {
	span, ctx := apm.StartSpan(ctx, "readSecret", "elasticsearch")
	defer span.End()
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

func WriteSecret(ctx context.Context, client *elasticsearch.Client, value string) (string, error) {
	span, ctx := apm.StartSpan(ctx, "writeSecret", "elasticsearch")
	defer span.End()
	es := ExtendedClient{Client: client, Custom: &ExtendedAPI{client}}
	return es.Custom.Write(ctx, value)
}

// Delete removes a secret from the Fleet secrets store.
// DELETE /_fleet/secret/secretId
func (c *ExtendedAPI) Delete(ctx context.Context, secretID string) error {
	req, err := http.NewRequestWithContext(ctx, "DELETE", "/_fleet/secret/"+secretID, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")

	res, err := c.Perform(req)
	if err != nil {
		return err
	}
	res.Body.Close()
	return nil
}

func DeleteSecret(ctx context.Context, client *elasticsearch.Client, secretID string) error {
	span, ctx := apm.StartSpan(ctx, "deleteSecret", "elasticsearch")
	defer span.End()
	es := ExtendedClient{Client: client, Custom: &ExtendedAPI{client}}
	return es.Custom.Delete(ctx, secretID)
}
