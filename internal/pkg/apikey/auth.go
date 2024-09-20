// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package apikey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/rs/zerolog"

	"github.com/elastic/fleet-server/v7/internal/pkg/es"
)

var (
	ErrUnauthorized           = errors.New("unauthorized")
	ErrElasticsearchAuthLimit = errors.New("elasticsearch auth limit")
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
func (k APIKey) Authenticate(ctx context.Context, client *elasticsearch.Client) (*SecurityInfo, error) {

	token := fmt.Sprintf("%s%s", authPrefix, k.Token())

	req := esapi.SecurityAuthenticateRequest{
		Header: map[string][]string{AuthKey: []string{token}},
	}

	res, err := req.Do(ctx, client)

	if err != nil {
		return nil, fmt.Errorf("apikey auth request %s: %w", k.ID, err)
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	if res.IsError() {
		var returnError error
		switch res.StatusCode {
		case http.StatusUnauthorized:
			returnError = ErrUnauthorized
		case http.StatusTooManyRequests:
			returnError = ErrElasticsearchAuthLimit
		}
		if returnError != nil {
			return nil, fmt.Errorf("%w: %w", returnError, fmt.Errorf("apikey auth response %s: %s", k.ID, res.String()))
		}
		return nil, es.ParseError(res, zerolog.Ctx(ctx))
	}

	var info SecurityInfo
	decoder := json.NewDecoder(res.Body)
	if err := decoder.Decode(&info); err != nil {
		return nil, fmt.Errorf("apikey auth parse %s: %w", k.ID, err)
	}

	return &info, nil
}
