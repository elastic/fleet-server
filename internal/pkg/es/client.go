// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package es

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"syscall"
	"time"

	"go.elastic.co/apm/module/apmelasticsearch/v2"

	"github.com/elastic/fleet-server/v7/internal/pkg/build"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/rs/zerolog"

	backoff "github.com/cenkalti/backoff/v4"
	"github.com/elastic/go-elasticsearch/v8"
)

const (
	initialRetryBackoff = 500 * time.Millisecond
	maxRetryBackoff     = 10 * time.Second
	randomizationFactor = 0.5
	defaultMaxRetries   = 5
)

type ConfigOption func(config *elasticsearch.Config)

func applyDefaultOptions(escfg *elasticsearch.Config) {
	exp := backoff.NewExponentialBackOff()
	exp.InitialInterval = initialRetryBackoff
	exp.RandomizationFactor = randomizationFactor
	exp.MaxInterval = maxRetryBackoff

	opts := []ConfigOption{
		WithRetryOnErrs(syscall.ECONNREFUSED, syscall.ECONNRESET), // server may be restarting

		WithRetryOnStatus(http.StatusTooManyRequests),
		WithRetryOnStatus(http.StatusRequestTimeout),
		WithRetryOnStatus(http.StatusTooEarly),
		WithRetryOnStatus(http.StatusBadGateway),
		WithRetryOnStatus(http.StatusServiceUnavailable),
		WithRetryOnStatus(http.StatusGatewayTimeout),

		WithBackoff(exp),
		WithMaxRetries(defaultMaxRetries),
	}

	for _, opt := range opts {
		opt(escfg)
	}
}

func NewClient(ctx context.Context, cfg *config.Config, longPoll bool, opts ...ConfigOption) (*elasticsearch.Client, error) {
	escfg, err := cfg.Output.Elasticsearch.ToESConfig(longPoll)
	if err != nil {
		return nil, err
	}
	addr := cfg.Output.Elasticsearch.Hosts
	mcph := cfg.Output.Elasticsearch.MaxConnPerHost

	// apply default config
	applyDefaultOptions(&escfg)

	// Apply configuration options
	for _, opt := range opts {
		opt(&escfg)
	}

	zlog := zerolog.Ctx(ctx).With().
		Strs("cluster.addr", addr).
		Int("cluster.maxConnsPersHost", mcph).
		Logger()

	zlog.Debug().Msg("init es")

	es, err := elasticsearch.NewClient(escfg)
	if err != nil {
		zlog.Error().Err(err).Msg("fail elasticsearch init")
		return nil, err
	}

	return es, nil
}

func WithUserAgent(name string, bi build.Info) ConfigOption {
	return func(config *elasticsearch.Config) {
		ua := userAgent(name, bi)
		// Set User-Agent header
		if config.Header == nil {
			config.Header = http.Header{}
		}
		config.Header.Set("User-Agent", ua)
	}
}

func InstrumentRoundTripper() ConfigOption {
	return func(config *elasticsearch.Config) {
		config.Transport = apmelasticsearch.WrapRoundTripper(
			config.Transport,
		)
	}
}

func WithRetryOnErrs(errs ...error) ConfigOption {
	return func(config *elasticsearch.Config) {
		config.RetryOnError = func(_ *http.Request, err error) bool {
			for _, e := range errs {
				if errors.Is(err, e) {
					return true
				}
			}
			return false
		}
	}
}

func WithMaxRetries(retries int) ConfigOption {
	return func(config *elasticsearch.Config) {
		config.MaxRetries = retries
	}
}

func WithRetryOnStatus(status int) ConfigOption {
	return func(config *elasticsearch.Config) {
		for _, s := range config.RetryOnStatus {
			// check for duplicities
			if s == status {
				return
			}
		}

		config.RetryOnStatus = append(config.RetryOnStatus, status)
	}
}

func WithBackoff(exp *backoff.ExponentialBackOff) ConfigOption {
	return func(config *elasticsearch.Config) {
		if exp == nil {
			// no retry backoff
			config.RetryBackoff = nil
			return
		}

		config.RetryBackoff = func(attempt int) time.Duration {
			if attempt == 1 {
				exp.Reset()
			}
			return exp.NextBackOff()
		}
	}
}

func userAgent(name string, bi build.Info) string {
	return fmt.Sprintf("Elastic-%s/%s (%s; %s; %s; %s)",
		name,
		bi.Version, runtime.GOOS, runtime.GOARCH,
		bi.Commit, bi.BuildTime)
}
