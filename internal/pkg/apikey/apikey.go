// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package apikey handles operations dealing with elasticsearch's API keys
package apikey

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
)

const (
	authPrefix = "ApiKey "
)

var (
	ErrNoAuthHeader    = errors.New("no authorization header")
	ErrMalformedHeader = errors.New("malformed authorization header")
	ErrMalformedToken  = errors.New("malformed token")
	ErrInvalidToken    = errors.New("token not valid utf8")
	ErrAPIKeyNotFound  = errors.New("api key not found")
)

var AuthKey = http.CanonicalHeaderKey("Authorization")

// APIKeyMetadata tracks Metadata associated with an APIKey.
type APIKeyMetadata struct {
	ID              string
	Metadata        Metadata
	RoleDescriptors json.RawMessage
}

// Read gathers APIKeyMetadata from Elasticsearch using the given client.
func Read(ctx context.Context, client *elasticsearch.Client, id string, withOwner bool) (*APIKeyMetadata, error) {

	opts := []func(*esapi.SecurityGetAPIKeyRequest){
		client.Security.GetAPIKey.WithContext(ctx),
		client.Security.GetAPIKey.WithID(id),
	}
	if withOwner {
		opts = append(opts, client.Security.GetAPIKey.WithOwner(true))
	}

	res, err := client.Security.GetAPIKey(
		opts...,
	)

	if err != nil {
		return nil, fmt.Errorf("request to elasticsearch failed: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("%s: %w", res.String(), ErrAPIKeyNotFound)
	}

	type APIKeyResponse struct {
		ID              string          `json:"id"`
		Metadata        Metadata        `json:"metadata"`
		RoleDescriptors json.RawMessage `json:"role_descriptors"`
	}
	type GetAPIKeyResponse struct {
		APIKeys []APIKeyResponse `json:"api_keys"`
	}

	var resp GetAPIKeyResponse
	d := json.NewDecoder(res.Body)
	if err = d.Decode(&resp); err != nil {
		return nil, fmt.Errorf(
			"could not decode elasticsearch GetAPIKeyResponse: %w", err)
	}

	if len(resp.APIKeys) == 0 {
		return nil, ErrAPIKeyNotFound
	}

	first := resp.APIKeys[0]

	return &APIKeyMetadata{
		ID:              first.ID,
		Metadata:        first.Metadata,
		RoleDescriptors: first.RoleDescriptors,
	}, nil
}

// APIKey is used to represent an Elasticsearch API Key.
type APIKey struct {
	ID  string
	Key string
}

// NewAPIKeyFromToken generates an APIKey from the given b64 encoded token.
func NewAPIKeyFromToken(token string) (*APIKey, error) {
	d, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(d) {
		return nil, ErrInvalidToken
	}
	s := strings.Split(string(d), ":")
	if len(s) != 2 {
		return nil, ErrMalformedToken
	}

	// interpret id:key
	apiKey := APIKey{
		ID:  s[0],
		Key: s[1],
	}

	return &apiKey, nil
}

// Token returns the b64 encoded token of the APIKey.
func (k APIKey) Token() string {
	s := fmt.Sprintf("%s:%s", k.ID, k.Key)
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// Agent provides a string consisting of "ID:Key"
func (k APIKey) Agent() string {
	return fmt.Sprintf("%s:%s", k.ID, k.Key)
}

// ExtractAPIKey gathers to APIKey associated with the request.
func ExtractAPIKey(r *http.Request) (*APIKey, error) {
	s, ok := r.Header[AuthKey]
	if !ok {
		return nil, ErrNoAuthHeader
	}
	if len(s) != 1 || !strings.HasPrefix(s[0], authPrefix) {
		return nil, ErrMalformedHeader
	}

	apiKeyStr := s[0][len(authPrefix):]
	apiKeyStr = strings.TrimSpace(apiKeyStr)
	return NewAPIKeyFromToken(apiKeyStr)
}
