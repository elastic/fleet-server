// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package es

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/elastic/go-elasticsearch/v8"
)

type versionInfo struct {
	Number string `json:"number"`
}

type infoResponse struct {
	Version versionInfo `json:"version"`
	Error   ErrorT      `json:"error,omitempty"`
}

func FetchESVersion(ctx context.Context, esCli *elasticsearch.Client) (version string, err error) {
	res, err := esCli.Info(
		esCli.Info.WithContext(ctx),
	)

	if err != nil {
		return
	}
	defer res.Body.Close()

	var sres infoResponse

	err = json.NewDecoder(res.Body).Decode(&sres)
	if err != nil {
		return
	}

	// Check error
	err = TranslateError(res.StatusCode, &sres.Error)
	if err != nil {
		return
	}

	verStr := strings.TrimSpace(strings.TrimSuffix(strings.ToLower(sres.Version.Number), "-snapshot"))

	return verStr, nil
}
