// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"
	"go.elastic.co/apm/v2"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
)

const (
	defaultKeyName        = "default.pgp"
	customKeyName         = "custom.pgp"
	customKeyMetadataName = "custom.url"
	defaultKeyPermissions = 0o0600
)

var (
	ErrTLSRequired    = errors.New("api call requires a TLS connection")
	ErrPGPPermissions = fmt.Errorf("pgp key permissions are not %#o", defaultKeyPermissions)
	ErrUpstreamStatus = errors.New("upstream http server status error")
)

type PGPRetrieverT struct {
	bulker bulk.Bulk
	cache  cache.Cache
	cfg    config.PGP
}

func NewPGPRetrieverT(ctx context.Context, cfg *config.Server, bulker bulk.Bulk, c cache.Cache) *PGPRetrieverT {
	pt := &PGPRetrieverT{
		bulker: bulker,
		cache:  c,
		cfg:    cfg.PGP,
	}
	if cfg.PGP.UpstreamURL != config.DefaultPGPUpstreamURL {
		metadata, err := os.ReadFile(filepath.Join(pt.cfg.Dir, customKeyMetadataName))
		if err != nil || string(metadata) != pt.cfg.UpstreamURL {
			if _, err := pt.FetchCustomKey(ctx); err != nil {
				zlog := zerolog.Ctx(ctx)
				zlog.Error().Err(err).Str("url", pt.cfg.UpstreamURL).Msg("Failed to fetch custom PGP key")
			}
		}
	}
	return pt
}

func (pt *PGPRetrieverT) handlePGPKey(zlog zerolog.Logger, w http.ResponseWriter, r *http.Request, _, _, _ int) error {
	if r.TLS == nil {
		return ErrTLSRequired
	}
	// auth is not required for this endpoint.
	// we also do not check if an API key is present in order to avoid making a round trip.
	ctx := zlog.WithContext(r.Context())

	p, err := pt.getPGPKey(ctx, zlog)
	if err != nil {
		return err
	}

	_, err = w.Write(p)
	return err
}

// getPGPKey will return the PGP key bytes
//
// First the local cache will be checked
// If it's not found in the cache, we attempt to read from disk
// If it's found we set the cache and return the bytes
// If it's not found on disk we attempt to retrieve the upstream key
// If that succeeds we set the cache then write to disk (with best effort).
func (pt *PGPRetrieverT) getPGPKey(ctx context.Context, zlog zerolog.Logger) ([]byte, error) {
	// key that will be retrieved, if this ever changes we should ensure that it can't be used as part of an injection attack as it is joined as part of the filepath for operations.
	key := filepath.Join(pt.cfg.Dir, defaultKeyName)

	span, ctx := apm.StartSpan(ctx, "getPGPKey", "process")
	span.Context.SetLabel("key", key)
	defer span.End()

	if pt.cfg.UpstreamURL != config.DefaultPGPUpstreamURL {
		key = filepath.Join(pt.cfg.Dir, customKeyName)
		span.Context.SetLabel("key", key)
		if p, ok := pt.cache.GetPGPKey(pt.cfg.UpstreamURL); ok {
			return p, nil
		}
		p, err := pt.getPGPFromDir(ctx, customKeyName)
		if err != nil {
			return pt.FetchCustomKey(ctx)
		}
		pt.cache.SetPGPKey(pt.cfg.UpstreamURL, p)
		return p, nil
	}

	p, ok := pt.cache.GetPGPKey(key)
	if ok {
		return p, nil
	}
	p, err := pt.getPGPFromDir(ctx, defaultKeyName)

	// successfully retrieved from disk
	if err == nil {
		pt.cache.SetPGPKey(key, p)
		return p, nil
	}

	// file exists but the read failed
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	// file does not exist
	p, err = pt.getPGPFromUpstream(ctx)
	if err != nil {
		return nil, err
	}
	pt.cache.SetPGPKey(key, p)
	pt.writeKeyToDir(ctx, zlog, key, p)
	return p, nil
}

// FetchCustomKey fetches the PGP key from the configured upstream URL and
// writes it to disk and the cache.
func (pt *PGPRetrieverT) FetchCustomKey(ctx context.Context) ([]byte, error) {
	zlog := zerolog.Ctx(ctx)
	p, err := pt.getPGPFromUpstream(ctx)
	if err != nil {
		return nil, err
	}
	key := filepath.Join(pt.cfg.Dir, customKeyName)
	if pt.writeKeyToDir(ctx, *zlog, key, p) {
		pt.writeKeyToDir(ctx, *zlog, filepath.Join(pt.cfg.Dir, customKeyMetadataName), []byte(pt.cfg.UpstreamURL))
	}
	pt.cache.SetPGPKey(pt.cfg.UpstreamURL, p)
	return p, nil
}

// getPGPFromDir will return the PGP contents if found in the directory
//
// Key contents are only returned if the key has valid permission bits.
// For the custom key, the metadata file is checked first and a URL mismatch
// returns fs.ErrNotExist.
func (pt *PGPRetrieverT) getPGPFromDir(ctx context.Context, keyName string) ([]byte, error) {
	span, _ := apm.StartSpan(ctx, "getPGPFromDir", "process")
	defer span.End()

	if keyName == customKeyName {
		metadata, err := os.ReadFile(filepath.Join(pt.cfg.Dir, customKeyMetadataName))
		if err != nil || string(metadata) != pt.cfg.UpstreamURL {
			return nil, fs.ErrNotExist
		}
	}

	key := filepath.Join(pt.cfg.Dir, keyName)
	stat, err := os.Stat(key)
	if err != nil {
		return nil, err
	}
	if stat.Mode().Perm() != defaultKeyPermissions { // TODO determine what permission bits we want to check
		return nil, ErrPGPPermissions
	}
	return os.ReadFile(key)
}

// getPGPFromUpstream returns the PGP key contentents from the key specified in the upstream URL.
func (pt *PGPRetrieverT) getPGPFromUpstream(ctx context.Context) ([]byte, error) {
	span, ctx := apm.StartSpan(ctx, "getPGPFromUpstream", "process")
	defer span.End()

	// NOTE: If we are concerned about this making too many requests we can add a lock, or use something like sync.Once
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pt.cfg.UpstreamURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %d", ErrUpstreamStatus, resp.StatusCode)
	}
	var b bytes.Buffer
	_, err = io.Copy(&b, resp.Body)
	return b.Bytes(), err
}

// writeKeyToDir will write the specified key to the keys directory
//
// If the directory does not exist it will create it
// Otherwise it is treated as a best-effort attempt
func (pt *PGPRetrieverT) writeKeyToDir(ctx context.Context, zlog zerolog.Logger, fullPath string, p []byte) bool {
	span, _ := apm.StartSpan(ctx, "writeKeyToDir", "process")
	defer span.End()

	_, err := os.Stat(pt.cfg.Dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			if err := os.Mkdir(pt.cfg.Dir, 0700); err != nil {
				zlog.Error().Err(err).Str("path", pt.cfg.Dir).Msgf("Unable to create directory")
				return false
			}
		} else {
			zlog.Error().Err(err).Str("path", pt.cfg.Dir).Msgf("Unable to verify if directory exists")
			return false
		}
	}

	err = os.WriteFile(fullPath, p, defaultKeyPermissions)
	if err != nil {
		zlog.Error().Err(err).Str("path", fullPath).Msg("Unable to write file.")
		return false
	}
	zlog.Info().Str("path", fullPath).Msg("Key written to storage.")
	return true
}
