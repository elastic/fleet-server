// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package esboot

import (
	"context"
	"encoding/json"
	"errors"
	"fleet/internal/pkg/es"
	"fleet/internal/pkg/esutil"
	"fmt"

	"github.com/rs/zerolog/log"
)

func CreateIndex(ctx context.Context, client *es.Client, name string) error {
	res, err := client.Indices.Create(name,
		client.Indices.Create.WithContext(ctx),
	)

	if err != nil {
		return err
	}

	defer res.Body.Close()

	err = esutil.CheckResponseError(res)
	if err != nil {
		if errors.Is(err, esutil.ErrResourceAlreadyExists) {
			log.Info().Str("name", name).Msg("Index already exists")
			return nil
		}
		return err
	}

	var r AckResponse
	err = json.NewDecoder(res.Body).Decode(&r)
	if err != nil {
		return fmt.Errorf("failed to parse create index response: %v, err: %v", name, err)
	}
	if !r.Acknowledged {
		return fmt.Errorf("failed to receive acknowledgment for create index request: %v", name)
	}

	return nil
}
