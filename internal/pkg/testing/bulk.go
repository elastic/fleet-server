// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testing

import (
	"context"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/gofrs/uuid"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
)

// MockBulk is a mock bulk interface.
type MockBulk struct {
}

func (m MockBulk) Create(ctx context.Context, index, id string, body []byte, opts ...bulk.Opt) (string, error) {
	i, err := uuid.NewV4()
	if err != nil {
		return "", err
	}
	return i.String(), nil
}

func (m MockBulk) Index(ctx context.Context, index, id string, body []byte, opts ...bulk.Opt) (string, error) {
	i, err := uuid.NewV4()
	if err != nil {
		return "", err
	}
	return i.String(), nil
}

func (m MockBulk) Update(ctx context.Context, index, id string, body []byte, opts ...bulk.Opt) error {
	return nil
}

func (m MockBulk) Read(ctx context.Context, index, id string, opts ...bulk.Opt) ([]byte, error) {
	return nil, nil
}

func (m MockBulk) Delete(ctx context.Context, index, id string, opts ...bulk.Opt) error {
	return nil
}

func (m MockBulk) MCreate(ctx context.Context, ops []bulk.MultiOp, opts ...bulk.Opt) ([]bulk.BulkIndexerResponseItem, error) {
	return nil, nil
}

func (m MockBulk) MIndex(ctx context.Context, ops []bulk.MultiOp, opts ...bulk.Opt) ([]bulk.BulkIndexerResponseItem, error) {
	return nil, nil
}

func (m MockBulk) MUpdate(ctx context.Context, ops []bulk.MultiOp, opts ...bulk.Opt) ([]bulk.BulkIndexerResponseItem, error) {
	return nil, nil
}

func (m MockBulk) MDelete(ctx context.Context, ops []bulk.MultiOp, opts ...bulk.Opt) ([]bulk.BulkIndexerResponseItem, error) {
	return nil, nil
}

func (m MockBulk) Search(ctx context.Context, index string, body []byte, opts ...bulk.Opt) (*es.ResultT, error) {
	return &es.ResultT{}, nil
}

func (m MockBulk) Client() *elasticsearch.Client {
	return nil
}

var _ bulk.Bulk = (*MockBulk)(nil)
