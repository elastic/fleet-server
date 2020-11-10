// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

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
)

var AuthKey = http.CanonicalHeaderKey("Authorization")

type ApiKey struct {
	Id  string
	Key string
}

func NewApiKeyFromToken(token string) (*ApiKey, error) {
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
	apiKey := ApiKey{
		Id:  s[0],
		Key: s[1],
	}

	return &apiKey, nil
}

func (k ApiKey) Token() string {
	s := fmt.Sprintf("%s:%s", k.Id, k.Key)
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func ExtractAPIKey(r *http.Request) (*ApiKey, error) {
	s, ok := r.Header[AuthKey]
	if !ok {
		return nil, ErrNoAuthHeader
	}
	if len(s) != 1 || !strings.HasPrefix(s[0], authPrefix) {
		return nil, ErrMalformedHeader
	}

	apiKeyStr := s[0][len(authPrefix):]
	apiKeyStr = strings.TrimSpace(apiKeyStr)
	return NewApiKeyFromToken(apiKeyStr)
}
