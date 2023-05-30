// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package apikey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
)

// SecurityInfo contains all related information about an APIKey that Elasticsearch tracks.
type SecurityInfo struct {
	UserName    string            `json:"username"`
	Roles       []string          `json:"roles"`
	FullName    string            `json:"full_name"`
	Email       string            `json:"email"`
	Metadata    json.RawMessage   `json:"metadata"`
	Enabled     bool              `json:"enabled"`
	AuthRealm   map[string]string `json:"authentication_realm"`
	LookupRealm map[string]string `json:"lookup_realm"`
}

// Authenticate will return the SecurityInfo associated with the APIKey (retrieved from Elasticsearch).
// Note: Prefer the bulk wrapper on this API
func (k APIKey) Authenticate(ctx context.Context, es *elasticsearch.Client) (*SecurityInfo, error) {

	token := fmt.Sprintf("%s%s", authPrefix, k.Token())

	req := esapi.SecurityAuthenticateRequest{
		Header: map[string][]string{AuthKey: []string{token}},
	}

	res, err := req.Do(ctx, es)

	if err != nil {
		return nil, fmt.Errorf("apikey auth request %s: %w", k.ID, err)
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	if res.IsError() {
		return nil, fmt.Errorf("%w: %w", ErrUnauthorized, fmt.Errorf("apikey auth response %s: %s", k.ID, res.String()))
	}

	var info SecurityInfo
	decoder := json.NewDecoder(res.Body)
	if err := decoder.Decode(&info); err != nil {
		return nil, fmt.Errorf("apikey auth parse %s: %w", k.ID, err)
	}

	return &info, nil
}
