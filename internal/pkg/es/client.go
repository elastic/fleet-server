// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package es

import (
	"context"
	"crypto/tls"
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

		// When the Elasticsearch output has multiple hosts whose certificates
		// chain to different CAs, a single untrusted host would otherwise fail
		// the request outright. Retrying lets the underlying connection pool's
		// dead-host failover redirect the attempt to a host that is still in
		// the live list.
		WithRetryOnTLSHandshakeError(),

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

// WithRetryOnTLSHandshakeError enables retries on TLS handshake failures such
// as certificate verification errors ("x509: certificate signed by unknown
// authority", expired certs, hostname mismatches, etc.).
//
// When the Elasticsearch output has multiple hosts whose certificates chain to
// different CAs, the underlying connection pool already marks a failed host
// dead via OnFailure on any transport error — but the request itself is only
// retried on a different host if RetryOnError returns true. Without this
// option, a TLS handshake failure against one host would abort the current
// request even when another host in the pool is still live and reachable.
//
// This option composes with any RetryOnError predicate already set on the
// config: the resulting predicate returns true if either the previously set
// one does, or the error is a TLS handshake error.
func WithRetryOnTLSHandshakeError() ConfigOption {
	return func(config *elasticsearch.Config) {
		prev := config.RetryOnError
		config.RetryOnError = func(req *http.Request, err error) bool {
			// Compose with any previously-installed RetryOnError predicate
			// (e.g. WithRetryOnErrs) using OR semantics: if the prior
			// predicate already wants to retry, honor that and short-circuit.
			// This way, layering this option on top of an existing classifier
			// only widens the set of retried errors and never clobbers it.
			if prev != nil && prev(req, err) {
				return true
			}
			return isTLSHandshakeError(err)
		}
	}
}

// isTLSHandshakeError reports whether err originated from a TLS certificate
// verification failure. These errors are surfaced by crypto/tls as
// *tls.CertificateVerificationError and are typically wrapped in a *url.Error
// and/or *net.OpError by the HTTP transport, so the check walks the unwrap
// chain via errors.As.
func isTLSHandshakeError(err error) bool {
	if err == nil {
		return false
	}
	var certErr *tls.CertificateVerificationError
	return errors.As(err, &certErr)
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
