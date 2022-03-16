// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testing

import (
	"context"

	"github.com/elastic/go-elasticsearch/v7"
	"github.com/gofrs/uuid"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
)

// MockBulk is a mock bulk interface.
type MockBulk struct {
	MockedAPIKey *bulk.ApiKey
	ArgumentData *InterfaceCapture
}

func NewMockBulk(apiKey *bulk.ApiKey) MockBulk {
	return MockBulk{
		MockedAPIKey: apiKey,
		ArgumentData: &InterfaceCapture{},
	}
}

type InterfaceCapture struct {
	Update []UpdateCapture
}

type UpdateCapture struct {
	index string
	id    string
	body  []byte
	opts  []bulk.Opt
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
	m.ArgumentData.Update = append(m.ArgumentData.Update, UpdateCapture{
		index: index,
		id:    id,
		body:  body,
		opts:  opts,
	})
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

func (m MockBulk) ApiKeyCreate(ctx context.Context, name, ttl string, roles []byte, meta interface{}) (*bulk.ApiKey, error) {
	return m.MockedAPIKey, nil
}

func (m MockBulk) ApiKeyRead(ctx context.Context, id string) (*bulk.ApiKeyMetadata, error) {
	return nil, nil
}

func (m MockBulk) ApiKeyAuth(ctx context.Context, key bulk.ApiKey) (*bulk.SecurityInfo, error) {
	return nil, nil
}

func (m MockBulk) ApiKeyInvalidate(ctx context.Context, ids ...string) error {
	return nil
}

var _ bulk.Bulk = (*MockBulk)(nil)
