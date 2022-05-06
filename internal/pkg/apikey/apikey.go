// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package apikey handles operations dealing with elasticsearch's API keys
package apikey

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"
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

type APIKey struct {
	ID  string
	Key string
}

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

func (k APIKey) Token() string {
	s := fmt.Sprintf("%s:%s", k.ID, k.Key)
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func (k APIKey) Agent() string {
	return fmt.Sprintf("%s:%s", k.ID, k.Key)
}

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
