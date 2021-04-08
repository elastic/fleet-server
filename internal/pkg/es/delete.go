// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package es

import (
	"context"
	"encoding/json"

	"github.com/elastic/go-elasticsearch/v8"
)

func DeleteIndices(ctx context.Context, es *elasticsearch.Client, indices []string) error {
	res, err := es.Indices.Delete(indices,
		es.Indices.Delete.WithContext(ctx),
	)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	var ares AckResponse
	err = json.NewDecoder(res.Body).Decode(&ares)
	if err != nil {
		return err
	}
	if !ares.Acknowledged {
		err = TranslateError(res.StatusCode, &ares.Error)
	}

	return err
}
