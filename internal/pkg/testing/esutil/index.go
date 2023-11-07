// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package esutil

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/rs/zerolog"
)

func CreateIndex(ctx context.Context, cli *elasticsearch.Client, name string) error {
	res, err := cli.Indices.Create(name,
		cli.Indices.Create.WithContext(ctx),
	)

	if err != nil {
		return err
	}

	defer res.Body.Close()

	err = checkResponseError(res)
	if err != nil {
		if errors.Is(err, ErrResourceAlreadyExists) {
			zerolog.Ctx(ctx).Info().Str("name", name).Msg("Index already exists")
			return nil
		}
		return err
	}

	var r AckResponse
	err = json.NewDecoder(res.Body).Decode(&r)
	if err != nil {
		return fmt.Errorf("failed to parse create index response: %s, err: %w", name, err)
	}
	if !r.Acknowledged {
		return fmt.Errorf("failed to receive acknowledgment for create index request: %s", name)
	}

	return nil
}

func DeleteIndices(ctx context.Context, cli *elasticsearch.Client, names ...string) error {
	res, err := cli.Indices.Delete(names,
		cli.Indices.Delete.WithContext(ctx),
	)

	if err != nil {
		return err
	}

	defer res.Body.Close()

	err = checkResponseError(res)
	if err != nil {
		return err
	}

	var r AckResponse
	err = json.NewDecoder(res.Body).Decode(&r)
	if err != nil {
		return fmt.Errorf("failed to parse delete indices response: %v, err: %w", names, err)
	}
	if !r.Acknowledged {
		return fmt.Errorf("failed to receive acknowledgment for delete indices request: %v", names)
	}

	return nil
}
