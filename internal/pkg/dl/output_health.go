// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import (
	"context"
	"encoding/json"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/gofrs/uuid"
)

type OutputHealth struct {
	Output    string `json:"output,omitempty"`
	State     string `json:"state,omitempty"`
	Message   string `json:"message,omitempty"`
	Timestamp string `json:"@timestamp,omitempty"`
}

func CreateOutputHealth(ctx context.Context, bulker bulk.Bulk, doc OutputHealth) error {
	return createOutputHealth(ctx, bulker, FleetOutputHealth, doc)
}

func createOutputHealth(ctx context.Context, bulker bulk.Bulk, index string, doc OutputHealth) error {
	if doc.Timestamp == "" {
		doc.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return err
	}

	id, err := uuid.NewV4()
	if err != nil {
		return err
	}
	_, err = bulker.Create(ctx, index, id.String(), body, bulk.WithRefresh())
	return err
}
