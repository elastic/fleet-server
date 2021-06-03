// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package apikey

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/elastic/go-elasticsearch/v7"
	"github.com/elastic/go-elasticsearch/v7/esapi"
)

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

// Kibana:
// https://github.com/elastic/kibana/blob/master/x-pack/plugins/security/server/authentication/authenticator.ts#L308
// NOTE: Bulk request currently not available.
func (k ApiKey) Authenticate(ctx context.Context, es *elasticsearch.Client) (*SecurityInfo, error) {

	token := fmt.Sprintf("%s%s", authPrefix, k.Token())

	req := esapi.SecurityAuthenticateRequest{
		Header: map[string][]string{AuthKey: []string{token}},
	}

	res, err := req.Do(ctx, es)

	if err != nil {
		return nil, fmt.Errorf("apikey auth request %s: %w", k.Id, err)
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	if res.IsError() {
		return nil, fmt.Errorf("apikey auth response %s: %s", k.Id, res.String())
	}

	var info SecurityInfo
	decoder := json.NewDecoder(res.Body)
	if err := decoder.Decode(&info); err != nil {
		return nil, fmt.Errorf("apikey auth parse %s: %w", k.Id, err)
	}

	return &info, nil
}
