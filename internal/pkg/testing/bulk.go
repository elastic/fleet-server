// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testing

import (
	"context"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"go.elastic.co/apm/v2"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
)

// MockBulk is a mock bulk interface that uses testify/mock.
type MockBulk struct {
	mock.Mock
}

func NewMockBulk() *MockBulk {
	return &MockBulk{}
}

func (m *MockBulk) Create(ctx context.Context, index, id string, body []byte, opts ...bulk.Opt) (string, error) {
	args := m.Called(ctx, index, id, body, opts)
	return args.String(0), args.Error(1)
}

func (m *MockBulk) Index(ctx context.Context, index, id string, body []byte, opts ...bulk.Opt) (string, error) {
	args := m.Called(ctx, index, id, body, opts)
	return args.String(0), args.Error(1)
}

func (m *MockBulk) Update(ctx context.Context, index, id string, body []byte, opts ...bulk.Opt) error {
	args := m.Called(ctx, index, id, body, opts)
	return args.Error(0)
}

func (m *MockBulk) Read(ctx context.Context, index, id string, opts ...bulk.Opt) ([]byte, error) {
	args := m.Called(ctx, index, id, opts)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockBulk) Delete(ctx context.Context, index, id string, opts ...bulk.Opt) error {
	args := m.Called(ctx, index, id, opts)
	return args.Error(0)
}

func (m *MockBulk) MCreate(ctx context.Context, ops []bulk.MultiOp, opts ...bulk.Opt) ([]bulk.BulkIndexerResponseItem, error) {
	args := m.Called(ctx, ops, opts)
	return args.Get(0).([]bulk.BulkIndexerResponseItem), args.Error(1)
}

func (m *MockBulk) MIndex(ctx context.Context, ops []bulk.MultiOp, opts ...bulk.Opt) ([]bulk.BulkIndexerResponseItem, error) {
	args := m.Called(ctx, ops, opts)
	return args.Get(0).([]bulk.BulkIndexerResponseItem), args.Error(1)
}

func (m *MockBulk) MUpdate(ctx context.Context, ops []bulk.MultiOp, opts ...bulk.Opt) ([]bulk.BulkIndexerResponseItem, error) {
	args := m.Called(ctx, ops, opts)
	return args.Get(0).([]bulk.BulkIndexerResponseItem), args.Error(1)
}

func (m *MockBulk) MDelete(ctx context.Context, ops []bulk.MultiOp, opts ...bulk.Opt) ([]bulk.BulkIndexerResponseItem, error) {
	args := m.Called(ctx, ops, opts)
	return args.Get(0).([]bulk.BulkIndexerResponseItem), args.Error(1)
}

func (m *MockBulk) Search(ctx context.Context, index string, body []byte, opts ...bulk.Opt) (*es.ResultT, error) {
	args := m.Called(ctx, index, body, opts)
	return args.Get(0).(*es.ResultT), args.Error(1)
}

func (m *MockBulk) Client() *elasticsearch.Client {
	args := m.Called()
	return args.Get(0).(*elasticsearch.Client)
}

func (m *MockBulk) GetBulker(outputName string) *bulk.Bulk {
	args := m.Called(outputName)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*bulk.Bulk)
}

func (m *MockBulk) GetBulkerMap() map[string]bulk.Bulk {
	args := m.Called()
	return args.Get(0).(map[string]bulk.Bulk)
}

func (m *MockBulk) CreateAndGetBulker(ctx context.Context, zlog zerolog.Logger, outputName string, outputMap map[string]map[string]interface{}) (bulk.Bulk, bool, error) {
	args := m.Called(ctx, zlog, outputName, outputMap)
	return args.Get(0).(bulk.Bulk), args.Get(1).(bool), nil
}

func (m *MockBulk) CancelFn() context.CancelFunc {
	args := m.Called()
	return args.Get(0).(context.CancelFunc)
}

func (m *MockBulk) ReadSecrets(ctx context.Context, secretIds []string) (map[string]string, error) {
	result := make(map[string]string)
	for _, id := range secretIds {
		result[id] = id + "_value"
	}
	return result, nil
}

func (m *MockBulk) APIKeyCreate(ctx context.Context, name, ttl string, roles []byte, meta interface{}) (*bulk.APIKey, error) {
	args := m.Called(ctx, name, ttl, roles, meta)
	return args.Get(0).(*bulk.APIKey), args.Error(1)
}

func (m *MockBulk) APIKeyRead(ctx context.Context, id string, _ bool) (*bulk.APIKeyMetadata, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*bulk.APIKeyMetadata), args.Error(1)
}

func (m *MockBulk) APIKeyAuth(ctx context.Context, key bulk.APIKey) (*bulk.SecurityInfo, error) {
	args := m.Called(ctx, key)
	return args.Get(0).(*bulk.SecurityInfo), args.Error(1)
}

func (m *MockBulk) APIKeyInvalidate(ctx context.Context, ids ...string) error {
	args := m.Called(ctx, ids)
	return args.Error(0)
}

func (m *MockBulk) APIKeyUpdate(ctx context.Context, id, outputPolicyHash string, roles []byte) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockBulk) HasTracer() bool {
	return false
}

func (m *MockBulk) StartTransaction(name, transactionType string) *apm.Transaction {
	return nil
}

var _ bulk.Bulk = (*MockBulk)(nil)
