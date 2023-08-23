// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cache

import (
	corecache "github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/file"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/stretchr/testify/mock"
)

type MockCache struct {
	mock.Mock
}

func NewMockCache() *MockCache {
	return &MockCache{}
}

func (m *MockCache) Reconfigure(cfg config.Cache) error {
	args := m.Called(cfg)
	return args.Error(0)
}

func (m *MockCache) SetAction(action model.Action) {
	m.Called(action)
}

func (m *MockCache) GetAction(id string) (model.Action, bool) {
	args := m.Called(id)
	return args.Get(0).(model.Action), args.Bool(1)
}

func (m *MockCache) SetAPIKey(key corecache.APIKey, enabled bool) {
	m.Called(key, enabled)
}

func (m *MockCache) ValidAPIKey(key corecache.APIKey) bool {
	args := m.Called(key)
	return args.Bool(0)
}

func (m *MockCache) SetEnrollmentAPIKey(id string, key model.EnrollmentAPIKey, cost int64) {
	m.Called(id, key, cost)
}

func (m *MockCache) GetEnrollmentAPIKey(id string) (model.EnrollmentAPIKey, bool) {
	args := m.Called(id)
	return args.Get(0).(model.EnrollmentAPIKey), args.Bool(1)
}

func (m *MockCache) SetArtifact(artifact model.Artifact) {
	m.Called(artifact)
}

func (m *MockCache) GetArtifact(ident, sha2 string) (model.Artifact, bool) {
	args := m.Called(ident, sha2)
	return args.Get(0).(model.Artifact), args.Bool(1)
}

func (m *MockCache) SetUpload(id string, info file.Info) {
	m.Called(id, info)
}

func (m *MockCache) GetUpload(id string) (file.Info, bool) {
	args := m.Called(id)
	return args.Get(0).(file.Info), args.Bool(1)
}
