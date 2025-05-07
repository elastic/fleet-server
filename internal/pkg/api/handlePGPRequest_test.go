// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/testing/cache"
	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func Test_PGPRetrieverT_getPGPKey(t *testing.T) {
	tests := []struct {
		name           string
		cache          func() *cache.MockCache
		dirSetup       func(t *testing.T) string
		upstreamStatus int
		content        []byte
		err            error
	}{{
		name: "found in cache",
		cache: func() *cache.MockCache {
			m := cache.NewMockCache()
			m.On("GetPGPKey", mock.Anything).Return([]byte("test"), true).Once()
			return m
		},
		dirSetup: func(t *testing.T) string {
			return ""
		},
		content: []byte("test"),
		err:     nil,
	}, {
		name: "found in dir",
		cache: func() *cache.MockCache {
			m := cache.NewMockCache()
			m.On("GetPGPKey", mock.Anything).Return([]byte{}, false).Once()
			m.On("SetPGPKey", mock.Anything, []byte("test")).Once()
			return m
		},
		dirSetup: func(t *testing.T) string {
			dir := t.TempDir()
			err := os.WriteFile(filepath.Join(dir, defaultKeyName), []byte("test"), defaultKeyPermissions)
			require.NoError(t, err)
			return dir
		},
		content: []byte("test"),
		err:     nil,
	}, {
		name: "found in dir with incorrect permissions",
		cache: func() *cache.MockCache {
			m := cache.NewMockCache()
			m.On("GetPGPKey", mock.Anything).Return([]byte{}, false).Once()
			return m
		},
		dirSetup: func(t *testing.T) string {
			dir := t.TempDir()
			err := os.WriteFile(filepath.Join(dir, defaultKeyName), []byte("test"), 0o0660) //nolint:gosec // we are testing for incorrect permissions
			require.NoError(t, err)
			return dir
		},
		content: nil,
		err:     ErrPGPPermissions,
	}, {
		name: "failed upstream request",
		cache: func() *cache.MockCache {
			m := cache.NewMockCache()
			m.On("GetPGPKey", mock.Anything).Return([]byte{}, false).Once()
			return m
		},
		dirSetup: func(t *testing.T) string {
			dir := t.TempDir()
			return dir
		},
		upstreamStatus: 400,
		content:        nil,
		err:            ErrUpstreamStatus,
	}, {
		name: "upstream request succeeded",
		cache: func() *cache.MockCache {
			m := cache.NewMockCache()
			m.On("GetPGPKey", mock.Anything).Return([]byte{}, false).Once()
			m.On("SetPGPKey", mock.Anything, []byte("test")).Once()
			return m
		},
		dirSetup: func(t *testing.T) string {
			dir := t.TempDir()
			return dir
		},
		upstreamStatus: 200,
		content:        []byte(`test`),
		err:            nil,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockCache := tc.cache()
			dir := tc.dirSetup(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.upstreamStatus)
				_, _ = w.Write([]byte(`test`))
			}))
			defer server.Close()

			pt := &PGPRetrieverT{
				cache: mockCache,
				cfg: config.PGP{
					UpstreamURL: server.URL,
					Dir:         dir,
				},
			}

			content, err := pt.getPGPKey(context.Background(), testlog.SetLogger(t))
			require.ErrorIs(t, err, tc.err)
			require.Equal(t, tc.content, content)
			mockCache.AssertExpectations(t)
		})
	}
}
