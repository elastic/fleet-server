// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package apikey

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
)

// Invalidate invalidates the provided API keys by ID.
func Invalidate(ctx context.Context, client *elasticsearch.Client, ids ...string) error {

	payload := struct {
		IDs   []string `json:"ids,omitempty"`
		Owner bool     `json:"owner"`
	}{
		ids,
		true,
	}

	body, err := json.Marshal(&payload)
	if err != nil {
		return err
	}

	opts := []func(*esapi.SecurityInvalidateAPIKeyRequest){
		client.Security.InvalidateAPIKey.WithContext(ctx),
	}

	res, err := client.Security.InvalidateAPIKey(
		bytes.NewReader(body),
		opts...,
	)

	if err != nil {
		return err
	}

	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("fail InvalidateAPIKey: %s", res.String())
	}
	return nil
}
