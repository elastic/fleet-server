// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package es

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/elastic/go-elasticsearch/v7"
)

// Refresh refreshes index. This is temporary code
// TODO: Remove this when the refresh is properly implemented on Eleasticsearch side
// The issue for "refresh" falls under phase 2 of https://github.com/elastic/elasticsearch/issues/71449.
// Once the phase 2 is complete we can remove the refreshes from fleet-server.
func Refresh(ctx context.Context, esCli *elasticsearch.Client, index string) error {
	res, err := esCli.Indices.Refresh(
		esCli.Indices.Refresh.WithContext(ctx),
		esCli.Indices.Refresh.WithIndex(index),
	)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	var esres Response
	err = json.NewDecoder(res.Body).Decode(&esres)
	if err != nil {
		return err
	}

	if res.IsError() {
		err = TranslateError(res.StatusCode, &esres.Error)
	}

	if err != nil {
		if errors.Is(err, ErrIndexNotFound) {
			return nil
		}
		return err
	}
	return nil
}
