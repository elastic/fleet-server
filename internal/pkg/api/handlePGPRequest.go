// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/rs/zerolog"
	"go.elastic.co/apm/v2"
)

const (
	defaultKeyName        = "default.pgp"
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

func NewPGPRetrieverT(cfg *config.Server, bulker bulk.Bulk, c cache.Cache) *PGPRetrieverT {
	return &PGPRetrieverT{
		bulker: bulker,
		cache:  c,
		cfg:    cfg.PGP,
	}
}

func (pt *PGPRetrieverT) handlePGPKey(zlog zerolog.Logger, w http.ResponseWriter, r *http.Request, _, _, _ int) error {
	if r.TLS == nil {
		return ErrTLSRequired
	}
	key, err := authAPIKey(r, pt.bulker, pt.cache)
	if err != nil {
		return err
	}
	zlog = zlog.With().Str(LogEnrollAPIKeyID, key.ID).Logger()
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

	p, ok := pt.cache.GetPGPKey(key)
	if ok {
		return p, nil
	}
	p, err := pt.getPGPFromDir(ctx, key)

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

// getPGPFromDir will return the PGP contents if found in the directory
//
// Key contents are only returned if the key has valid permission bits.
func (pt *PGPRetrieverT) getPGPFromDir(ctx context.Context, key string) ([]byte, error) {
	span, _ := apm.StartSpan(ctx, "getPGPFromDir", "process")
	defer span.End()

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
	return io.ReadAll(resp.Body)
}

// writeKeyToDir will write the specified key to the keys directory
//
// If the directory does not exist it will create it
// Otherwise it is treated as a best-effort attempt
func (pt *PGPRetrieverT) writeKeyToDir(ctx context.Context, zlog zerolog.Logger, fullPath string, p []byte) {
	span, _ := apm.StartSpan(ctx, "writeKeyToDir", "process")
	defer span.End()

	_, err := os.Stat(pt.cfg.Dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			if err := os.Mkdir(pt.cfg.Dir, 0700); err != nil {
				zlog.Error().Err(err).Str("path", pt.cfg.Dir).Msgf("Unable to create directory")
				return
			}
		} else {
			zlog.Error().Err(err).Str("path", pt.cfg.Dir).Msgf("Unable to verify if directory exists")
			return
		}
	}

	err = os.WriteFile(fullPath, p, defaultKeyPermissions)
	if err != nil {
		zlog.Error().Err(err).Str("path", fullPath).Msg("Unable to write file.")
		return
	}
	zlog.Info().Str("path", fullPath).Msg("Key written to storage.")

}
