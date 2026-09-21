// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package apikey

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/rs/zerolog"

	"github.com/elastic/fleet-server/v7/internal/pkg/es"
)

// Invalidate invalidates the provided API keys by ID.
// It logs a warning for any key that ES did not actually invalidate (not found
// or already invalidated), and returns an error if ES reported invalidation errors.
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
		return fmt.Errorf("InvalidateAPIKey: %w", err)
	}

	opts := []func(*esapi.SecurityInvalidateAPIKeyRequest){
		client.Security.InvalidateAPIKey.WithContext(ctx),
	}

	res, err := client.Security.InvalidateAPIKey(
		bytes.NewReader(body),
		opts...,
	)
	if err != nil {
		return fmt.Errorf("InvalidateAPIKey: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("fail InvalidateAPIKey: %w", es.TranslateError(res.StatusCode, nil))
	}

	var result struct {
		InvalidatedAPIKeys           []string `json:"invalidated_api_keys"`
		PreviouslyInvalidatedAPIKeys []string `json:"previously_invalidated_api_keys"`
		ErrorCount                   int      `json:"error_count"`
	}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return fmt.Errorf("InvalidateAPIKey decode: %w", err)
	}

	// Build a set of IDs that ES acted on (newly or previously invalidated).
	actioned := make(map[string]struct{}, len(result.InvalidatedAPIKeys)+len(result.PreviouslyInvalidatedAPIKeys))
	for _, id := range result.InvalidatedAPIKeys {
		actioned[id] = struct{}{}
	}
	for _, id := range result.PreviouslyInvalidatedAPIKeys {
		actioned[id] = struct{}{}
	}
	for _, id := range ids {
		if _, ok := actioned[id]; !ok {
			zerolog.Ctx(ctx).Warn().Str("api_key.id", id).Msg("API key not found during invalidation; it may have already expired")
		}
	}

	if result.ErrorCount > 0 {
		return fmt.Errorf("InvalidateAPIKey: ES reported %d error(s) invalidating keys", result.ErrorCount)
	}

	return nil
}
