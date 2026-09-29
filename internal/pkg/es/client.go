// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

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

	backoff "github.com/cenkalti/backoff/v7"
	"github.com/elastic/elastic-transport-go/v8/elastictransport"
	"github.com/elastic/go-elasticsearch/v8"
)

const (
	initialRetryBackoff = 500 * time.Millisecond
	maxRetryBackoff     = 10 * time.Second
	randomizationFactor = 0.5
	defaultMaxRetries   = 5
)

// ConfigOption configures the Elasticsearch client built by NewClient.
// Obtain values using the With* functions in this package.
type ConfigOption struct {
	esOpts []elasticsearch.Option
	rtWrap func(http.RoundTripper) http.RoundTripper
}

func newESOption(opt elasticsearch.Option) ConfigOption {
	return ConfigOption{esOpts: []elasticsearch.Option{opt}}
}

// NewConfigOption wraps one or more elasticsearch.Option values as a ConfigOption.
// Prefer the typed With* helpers in this package; use this only when you need
// to pass a raw elasticsearch option that has no helper (e.g. in tests).
func NewConfigOption(opts ...elasticsearch.Option) ConfigOption {
	return ConfigOption{esOpts: opts}
}

func defaultOptions(disableRetry bool) []elasticsearch.Option {
	if disableRetry {
		return []elasticsearch.Option{
			elasticsearch.WithTransportOptions(elastictransport.WithDisableRetry()),
		}
	}

	exp := backoff.NewExponentialBackOff()
	exp.InitialInterval = initialRetryBackoff
	exp.RandomizationFactor = randomizationFactor
	exp.MaxInterval = maxRetryBackoff

	return []elasticsearch.Option{
		elasticsearch.WithTransportOptions(
			elastictransport.WithRetryOnError(func(_ *http.Request, err error) bool {
				// Retry on connection refused/reset (server may be restarting) and TLS
				// handshake failures. The latter matters when multiple ES hosts have
				// certificates chaining to different CAs: a single bad host should not
				// abort the request when another live host is available.
				return errors.Is(err, syscall.ECONNREFUSED) ||
					errors.Is(err, syscall.ECONNRESET) ||
					isTLSHandshakeError(err)
			}),
			elastictransport.WithRetryOnStatus(
				http.StatusTooManyRequests,
				http.StatusRequestTimeout,
				http.StatusTooEarly,
				http.StatusBadGateway,
				http.StatusServiceUnavailable,
				http.StatusGatewayTimeout,
			),
			elastictransport.WithRetryBackoff(func(attempt int) time.Duration {
				if attempt == 1 {
					exp.Reset()
				}
				return exp.NextBackOff()
			}),
			elastictransport.WithMaxRetries(defaultMaxRetries),
		),
	}
}

func NewClient(ctx context.Context, cfg *config.Config, longPoll bool, opts ...ConfigOption) (*elasticsearch.Client, error) {
	tCfg, err := cfg.Output.Elasticsearch.ToESTransportConfig(longPoll)
	if err != nil {
		return nil, err
	}
	addr := cfg.Output.Elasticsearch.Hosts
	mcph := cfg.Output.Elasticsearch.MaxConnPerHost

	// Apply any transport wrappers (e.g. APM instrumentation) in order.
	var rt http.RoundTripper = tCfg.Transport
	var callerESopts []elasticsearch.Option
	for _, opt := range opts {
		if opt.rtWrap != nil {
			rt = opt.rtWrap(rt)
		}
		callerESopts = append(callerESopts, opt.esOpts...)
	}

	// Build base client options from the resolved transport config.
	baseOpts := []elasticsearch.Option{
		elasticsearch.WithAddresses(tCfg.Addresses...),
		elasticsearch.WithTransportOptions(
			elastictransport.WithTransport(rt),
			elastictransport.WithHeader(tCfg.Header),
		),
	}
	if tCfg.ServiceToken != "" {
		baseOpts = append(baseOpts, elasticsearch.WithServiceToken(tCfg.ServiceToken))
	}

	zlog := zerolog.Ctx(ctx).With().
		Strs("cluster.addr", addr).
		Int("cluster.maxConnsPersHost", mcph).
		Logger()

	zlog.Debug().Msg("init es")

	allOpts := append(append(baseOpts, defaultOptions(tCfg.DisableRetry)...), callerESopts...)
	es, err := elasticsearch.New(allOpts...)
	if err != nil {
		zlog.Error().Err(err).Msg("fail elasticsearch init")
		return nil, err
	}

	return es, nil
}

func WithUserAgent(name string, bi build.Info) ConfigOption {
	return newESOption(elasticsearch.WithTransportOptions(
		elastictransport.WithUserAgent(userAgent(name, bi)),
	))
}

// InstrumentRoundTripper wraps the underlying HTTP transport with APM tracing.
// Apply this option when APM instrumentation is enabled.
func InstrumentRoundTripper() ConfigOption {
	return ConfigOption{
		rtWrap: func(rt http.RoundTripper) http.RoundTripper {
			return apmelasticsearch.WrapRoundTripper(rt)
		},
	}
}

func WithRetryOnErrs(errs ...error) ConfigOption {
	return newESOption(elasticsearch.WithTransportOptions(
		elastictransport.WithRetryOnError(func(_ *http.Request, err error) bool {
			for _, e := range errs {
				if errors.Is(err, e) {
					return true
				}
			}
			return false
		}),
	))
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
func WithRetryOnTLSHandshakeError() ConfigOption {
	return newESOption(elasticsearch.WithTransportOptions(
		elastictransport.WithRetryOnError(func(_ *http.Request, err error) bool {
			return isTLSHandshakeError(err)
		}),
	))
}

// isTLSHandshakeError reports whether err originated from a TLS certificate
// verification failure. These errors are surfaced by crypto/tls as
// *tls.CertificateVerificationError and are typically wrapped in a *url.Error
// and/or *net.OpError by the HTTP transport, so the check walks the unwrap
// chain via errors.As.
func isTLSHandshakeError(err error) bool {
	var certErr *tls.CertificateVerificationError
	return errors.As(err, &certErr)
}

func WithMaxRetries(retries int) ConfigOption {
	return newESOption(elasticsearch.WithTransportOptions(
		elastictransport.WithMaxRetries(retries),
	))
}

func WithRetryOnStatus(status int) ConfigOption {
	return newESOption(elasticsearch.WithTransportOptions(
		elastictransport.WithRetryOnStatus(status),
	))
}

func WithBackoff(exp *backoff.ExponentialBackOff) ConfigOption {
	if exp == nil {
		return newESOption(elasticsearch.WithTransportOptions(
			elastictransport.WithRetryBackoff(nil),
		))
	}
	return newESOption(elasticsearch.WithTransportOptions(
		elastictransport.WithRetryBackoff(func(attempt int) time.Duration {
			if attempt == 1 {
				exp.Reset()
			}
			return exp.NextBackOff()
		}),
	))
}

func userAgent(name string, bi build.Info) string {
	return fmt.Sprintf("Elastic-%s/%s (%s; %s; %s; %s)",
		name,
		bi.Version, runtime.GOOS, runtime.GOARCH,
		bi.Commit, bi.BuildTime)
}
