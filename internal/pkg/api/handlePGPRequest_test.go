// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

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

			upstreamURL := config.DefaultPGPUpstreamURL
			if tc.upstreamStatus != 0 {
				upstreamURL = server.URL
			}
			pt := &PGPRetrieverT{
				cache: mockCache,
				cfg: config.PGP{
					UpstreamURL: upstreamURL,
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

func TestPGPKeyCustomUpstream(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/one":
			_, _ = w.Write([]byte("first key"))
		case "/two":
			_, _ = w.Write([]byte("second key"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	defaultPath := filepath.Join(dir, defaultKeyName)
	require.NoError(t, os.WriteFile(defaultPath, []byte("default key"), defaultKeyPermissions))

	newMock := func(key []byte) *cache.MockCache {
		m := cache.NewMockCache()
		m.On("DeletePGPKey", mock.Anything).Once()
		m.On("GetPGPKey", mock.Anything).Return([]byte(nil), false).Once()
		m.On("SetPGPKey", mock.Anything, key).Once()
		return m
	}

	cfg := &config.Server{PGP: config.PGP{UpstreamURL: server.URL + "/one", Dir: dir}}
	pt := NewPGPRetrieverT(cfg, nil, newMock([]byte("first key")))
	p, err := pt.getPGPKey(t.Context(), testlog.SetLogger(t))
	require.NoError(t, err)
	require.Equal(t, []byte("first key"), p)

	cfg.PGP.UpstreamURL = server.URL + "/two"
	pt = NewPGPRetrieverT(cfg, nil, newMock([]byte("second key")))
	p, err = pt.getPGPKey(t.Context(), testlog.SetLogger(t))
	require.NoError(t, err)
	require.Equal(t, []byte("second key"), p)

	server.Close()
	pt = NewPGPRetrieverT(cfg, nil, newMock([]byte("second key")))
	p, err = pt.getPGPKey(t.Context(), testlog.SetLogger(t))
	require.NoError(t, err)
	require.Equal(t, []byte("second key"), p)

	stored, err := os.ReadFile(defaultPath)
	require.NoError(t, err)
	require.Equal(t, "default key", string(stored))
}
